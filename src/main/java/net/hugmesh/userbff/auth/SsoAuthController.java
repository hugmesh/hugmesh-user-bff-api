package net.hugmesh.userbff.auth;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import net.hugmesh.authcore.config.SessionCookieService;
import net.hugmesh.authcore.config.SessionCookieWebFilter;
import net.hugmesh.authcore.web.dto.RegisterEmailRequest;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The login / registration / session surface owned by user-bff. The headline entrypoint is
 * NATIVE LOGIN: the browser posts {@code {username, password}} and this BFF verifies the
 * credential SERVER-SIDE against the INTERNAL Casdoor ({@link CasdoorLoginClient}) — Casdoor
 * is NEVER browser-exposed and the browser NEVER receives a JWT/access/refresh/id token, the
 * PKCE {@code code_verifier}, the {@code state}, or any Casdoor URL. Every account/session
 * write is DELEGATED to {@link AdminBffInternalClient} (admin-bff owns those tables; user-bff
 * has no such DB).
 *
 * <ul>
 *   <li>{@code POST /bff/login} — <b>native login</b>: server-side PKCE + state, verify creds
 *       at Casdoor {@code /api/login}; on {@code code} run the shared completion (exchange →
 *       provision → custody → {@code bff_} cookie); on MFA-required return a challenge (no
 *       cookie); on bad creds return {@code 401 invalid_credentials};</li>
 *   <li>{@code POST /bff/register} — email-provider registration; ensures the account +
 *       mints a session;</li>
 *   <li>{@code DELETE /bff/session} — the {@code /sessionOut} leg (revoke the session);</li>
 *   <li>{@code GET /bff/me} — the caller's account view (authenticated; NOT permitAll);</li>
 *   <li>{@code GET /bff/session} — the SAME view, permitAll + cookie-authenticated so the
 *       login SPA can hydrate straight after login (it then holds only the {@code bff_} cookie).</li>
 * </ul>
 *
 * <p>SHIPS DARK: with {@code app.bff.oidc.enabled=false} (the default) the
 * {@link CasdoorLoginClient}, the {@link OidcLoginCompletionService}'s exchange client, and
 * the {@link AdminBffInternalClient} are all fail-closed stubs, so {@code /login},
 * {@code /register} and {@code /session} resolve to {@code Mono.error} (503) — never a silent
 * success. Flip the flag (and provision the custody key + internal token) to go live.
 *
 * @see CasdoorLoginClient
 * @see OidcLoginCompletionService
 */
@Tag(name = "SSO auth", description =
        "Native login (server-side credential check) / register / session. Ships dark behind app.bff.oidc.enabled.")
@RestController
@RequestMapping("/bff")
public class SsoAuthController {

    /**
     * The native-login request body. {@code username} + {@code password} are the credentials
     * verified server-side against Casdoor; {@code mfaPasscode} + {@code mfaType} complete a
     * second-factor challenge on the follow-up call (both optional).
     */
    public record NativeLoginRequest(String username, String password,
                                     String mfaPasscode, String mfaType) {}

    /** Success body — non-secret routing hints ONLY. NEVER a token/JWT. */
    public record LoginResult(boolean registrationComplete, String status, boolean mfaRequired) {}

    /** MFA-challenge body — a second factor is required; NO session was minted. */
    public record MfaChallenge(boolean mfaRequired, List<String> mfaType) {
        // Copy on the way IN and OUT so this response body cannot be mutated by (or
        // through) the caller after construction. Null is preserved; the accessor maps
        // it to an empty list.
        public MfaChallenge {
            mfaType = mfaType == null ? null : List.copyOf(mfaType);
        }

        @Override
        public List<String> mfaType() {
            return mfaType == null ? List.of() : List.copyOf(mfaType);
        }
    }

    /** Bad-credential body — a stable error code + Casdoor's (non-secret) message. */
    public record LoginError(String error, String message) {}

    private final CasdoorLoginClient casdoorLogin;
    private final OidcLoginCompletionService completion;
    private final AdminBffInternalClient adminBff;
    private final SessionCookieService cookies;
    private final String redirectUri;

    public SsoAuthController(CasdoorLoginClient casdoorLogin,
                            OidcLoginCompletionService completion,
                            AdminBffInternalClient adminBff,
                            SessionCookieService cookies,
                            @Value("${app.bff.oidc.redirect-uri:https://hugmesh.net/login/callback}")
                            String redirectUri) {
        this.casdoorLogin = casdoorLogin;
        this.completion = completion;
        this.adminBff = adminBff;
        this.cookies = cookies;
        this.redirectUri = redirectUri;
    }

    @Operation(summary = "Native login: verify username+password SERVER-SIDE at Casdoor, then "
            + "exchange the code, provision the account+session and set the bff_ cookie. "
            + "200 {registrationComplete,status,mfaRequired:false} on success; 200 {mfaRequired:true} "
            + "when a second factor is needed (no cookie); 401 invalid_credentials on bad creds. "
            + "503 when the SSO surface is dark.")
    @PostMapping("/login")
    public Mono<ResponseEntity<Object>> login(@RequestBody NativeLoginRequest req,
                                              ServerWebExchange exchange) {
        // Generate the PKCE pair + state SERVER-SIDE — none of these ever reach the browser.
        Pkce pkce = Pkce.generate();
        String state = Pkce.randomState();
        return casdoorLogin.login(req.username(), req.password(), state, pkce.challenge(),
                        redirectUri, req.mfaPasscode(), req.mfaType())
                .flatMap(result -> switch (result.kind()) {
                    // Credentials verified → redeem the one-time code via the SHARED completion
                    // (exchange → provision → custody → bff_ cookie). No token reaches the browser.
                    case CODE -> completion.complete(result.code(), pkce.verifier(), redirectUri, exchange)
                            .map(c -> ResponseEntity.ok((Object)
                                    new LoginResult(c.registrationComplete(), c.status(), false)));
                    // Second factor required → challenge the caller. NO session, NO cookie.
                    case MFA_REQUIRED -> Mono.just(ResponseEntity.ok((Object)
                            new MfaChallenge(true, result.mfaTypes())));
                    // Bad password / disabled user / wrong passcode → 401, no session.
                    case ERROR -> Mono.just(ResponseEntity.status(HttpStatus.UNAUTHORIZED).body((Object)
                            new LoginError("invalid_credentials", result.message())));
                });
    }

    @Operation(summary = "Email-provider registration: ensure the account. "
            + "503 when the SSO surface is dark.")
    @PostMapping("/register")
    public Mono<ResponseEntity<Map<String, Object>>> register(@RequestBody RegisterEmailRequest req,
                                                              ServerWebExchange exchange) {
        // Gate the account-provisioning entrypoint on the allowlist so an unlisted email cannot
        // self-provision an account + session via /register (this is a permitAll, mutating
        // surface). 403 BEFORE ensureAccount when not allowed; fail-closed.
        return adminBff.allowlistCheck("email", req.email())
                .flatMap(allowed -> Boolean.TRUE.equals(allowed)
                        ? adminBff.ensureAccount("email", req.email())
                        : Mono.error(new ResponseStatusException(HttpStatus.FORBIDDEN,
                                "not allowed to register")))
                .flatMap(account -> adminBff.createSession(account.id())
                        .map(session -> emitAndSession(exchange, account, session)));
    }

    @Operation(summary = "Revoke the caller's session (sessionOut) and expire the bff_ cookie. "
            + "503 when the SSO surface is dark.")
    @DeleteMapping("/session")
    public Mono<ResponseEntity<Void>> sessionOut(ServerWebExchange exchange) {
        String token = bffTokenFrom(exchange);
        if (token == null) {
            return Mono.just(ResponseEntity.noContent().build());
        }
        return adminBff.deleteSession(token).thenReturn(expireCookie());
    }

    @Operation(summary = "The caller's account view (from admin-bff). Authenticated. "
            + "503 when the SSO surface is dark.")
    @GetMapping("/me")
    public Mono<Map<String, Object>> me(ServerWebExchange exchange) {
        return sessionView(exchange);
    }

    @Operation(summary = "The caller's session view (from admin-bff), read from the bff_ cookie. "
            + "PermitAll + cookie-authenticated (NO JWT) so the login SPA can hydrate its session "
            + "straight after login — when the browser holds only the bff_ cookie, not a "
            + "gateway-minted JWT (which is what /me requires). Same body as /me. 401 when there is no "
            + "session; 503 when the SSO surface is dark.")
    @GetMapping("/session")
    public Mono<Map<String, Object>> session(ServerWebExchange exchange) {
        return sessionView(exchange);
    }

    /**
     * The caller's account/session view, keyed on the opaque {@code bff_} cookie and resolved
     * via admin-bff. Shared by {@code GET /bff/me} (JWT-authenticated) and {@code GET /bff/session}
     * (permitAll, cookie-only — the login-ui hydrate path). 401 when no cookie; fail-closed 503
     * (stub error) while the SSO surface is dark — never a fabricated local view.
     */
    private Mono<Map<String, Object>> sessionView(ServerWebExchange exchange) {
        String token = bffTokenFrom(exchange);
        if (token == null) {
            return Mono.error(new ResponseStatusException(HttpStatus.UNAUTHORIZED, "no session"));
        }
        // Resolve the account FROM the opaque session token (admin-bff introspect → account id →
        // full view). NOT getAccount(token): a bff_ session token is never an account id
        // (provider:handle), so getAccount(token) always 404'd — /bff/me + /bff/session both
        // failed (masked while the SSO surface shipped dark).
        return adminBff.getAccountBySession(token)
                .map(account -> {
                    Map<String, Object> out = new LinkedHashMap<>();
                    out.put("id", account.id());
                    out.put("provider", account.provider());
                    out.put("handle", account.handle());
                    out.put("registrationComplete", account.registrationComplete());
                    out.put("roles", account.roles());
                    return out;
                });
    }

    /**
     * admin-bff {@code emitAndSession} parity for {@code /register}: mint the opaque {@code bff_}
     * cookie (when {@code app.session.cookie.enabled}) AND keep the token in the body (vestigial)
     * so existing token-in-body clients keep working. NOTE: {@code /login} deliberately does NOT
     * use this — a native-login response NEVER carries the session token in the body (cookie only).
     */
    private ResponseEntity<Map<String, Object>> emitAndSession(
            ServerWebExchange exchange, AdminBffInternalClient.AccountView account,
            AdminBffInternalClient.SessionView session) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("token", session.token());
        body.put("id", account.id());
        body.put("provider", account.provider());
        body.put("registrationComplete", account.registrationComplete());
        body.put("roles", account.roles());
        ResponseEntity.BodyBuilder builder = ResponseEntity.ok();
        if (cookies.enabled()) {
            builder.header("Set-Cookie", cookies.mint(exchange.getRequest(), session.token()).toString());
        }
        return builder.body(body);
    }

    private ResponseEntity<Void> expireCookie() {
        if (cookies.enabled()) {
            ResponseCookie expired = cookies.expire();
            return ResponseEntity.noContent().header("Set-Cookie", expired.toString()).build();
        }
        return ResponseEntity.noContent().build();
    }

    /** The opaque {@code bff_} session token from the cookie (the only place user-bff
     *  reads it). Null when absent — callers fail closed. */
    private static String bffTokenFrom(ServerWebExchange exchange) {
        var cookie = exchange.getRequest().getCookies()
                .getFirst(SessionCookieWebFilter.SESSION_COOKIE);
        return cookie == null ? null : cookie.getValue();
    }
}
