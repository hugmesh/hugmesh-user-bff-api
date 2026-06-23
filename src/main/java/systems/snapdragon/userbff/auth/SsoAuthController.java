package systems.snapdragon.userbff.auth;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
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
import systems.snapdragon.authcore.config.SessionCookieService;
import systems.snapdragon.authcore.config.SessionCookieWebFilter;
import systems.snapdragon.authcore.web.dto.LoginRequest;
import systems.snapdragon.authcore.web.dto.RegisterEmailRequest;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The login/registration/session surface MIRRORING admin-bff's {@code AuthController},
 * relocated to user-bff so this BFF owns login. EVERY account/session operation is
 * DELEGATED to {@link AdminBffInternalClient} (admin-bff owns the account + bff_session
 * tables; user-bff has no such DB — no auth-core {@code AccountStore}/
 * {@code BffSessionRepository} bean is instantiated here). The opaque {@code bff_}
 * session is minted via {@link SessionCookieService} (cookie ships dark) while the token
 * is ALSO returned in the body, matching admin-bff's {@code emitAndSession()} parity.
 *
 * <ul>
 *   <li>{@code POST /bff/login} — provider login; ensures the account + mints a session;</li>
 *   <li>{@code POST /bff/register} — email-provider registration; ensures the account;</li>
 *   <li>{@code DELETE /bff/session} — the {@code /sessionOut} leg (revoke the session);</li>
 *   <li>{@code GET /bff/me} — the caller's account view (from admin-bff, NOT a local DB);
 *       kept AUTHENTICATED (matches admin-bff) — NOT in the permitAll set.</li>
 * </ul>
 *
 * <p>SHIPS DARK: with {@code app.bff.oidc.enabled=false} (the default) the
 * {@link AdminBffInternalClient} is a fail-closed stub, so {@code /login},
 * {@code /register} and {@code /session} resolve to {@code Mono.error} (503) — never a
 * silent success. {@code /me} returns 503 the same way. Flip the flag (and provision
 * the internal token + custody key) to go live.
 */
@Tag(name = "SSO auth", description =
        "Login / register / session surface, delegating to admin-bff internal. Ships dark behind app.bff.oidc.enabled.")
@RestController
@RequestMapping("/bff")
public class SsoAuthController {

    private final AdminBffInternalClient adminBff;
    private final SessionCookieService cookies;

    public SsoAuthController(AdminBffInternalClient adminBff, SessionCookieService cookies) {
        this.adminBff = adminBff;
        this.cookies = cookies;
    }

    @Operation(summary = "Provider login: ensure the account and mint an opaque bff_ session "
            + "(cookie + body). 503 when the SSO surface is dark.")
    @PostMapping("/login")
    public Mono<ResponseEntity<Map<String, Object>>> login(@RequestBody LoginRequest req,
                                                           ServerWebExchange exchange) {
        String handle = handleOf(req);
        return adminBff.allowlistCheck(req.provider(), handle)
                .flatMap(allowed -> Boolean.TRUE.equals(allowed)
                        ? adminBff.ensureAccount(req.provider(), handle)
                        : Mono.error(new ResponseStatusException(HttpStatus.FORBIDDEN,
                                "not allowed to log in")))
                .flatMap(account -> adminBff.createSession(account.id())
                        .map(session -> emitAndSession(exchange, account, session)));
    }

    @Operation(summary = "Email-provider registration: ensure the account. "
            + "503 when the SSO surface is dark.")
    @PostMapping("/register")
    public Mono<ResponseEntity<Map<String, Object>>> register(@RequestBody RegisterEmailRequest req,
                                                              ServerWebExchange exchange) {
        return adminBff.ensureAccount("email", req.email())
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
        String token = bffTokenFrom(exchange);
        if (token == null) {
            return Mono.error(new ResponseStatusException(HttpStatus.UNAUTHORIZED, "no session"));
        }
        // The session token resolves to an account view via admin-bff (#112). Until that
        // contract is pinned the internal client errors (stub) — fail closed, never a
        // fabricated local view.
        return adminBff.getAccount(token)
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
     * admin-bff {@code emitAndSession} parity: mint the opaque {@code bff_} cookie (only
     * when {@code app.session.cookie.enabled}; ships dark) AND keep the token in the body
     * so the existing token-in-body clients are byte-identical until the cookie is flipped.
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

    private static String handleOf(LoginRequest req) {
        if (req.email() != null && !req.email().isBlank()) {
            return req.email();
        }
        return req.username();
    }
}
