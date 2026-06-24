package systems.snapdragon.userbff.auth;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import systems.snapdragon.authcore.casdoor.BffCustodyCipher;
import systems.snapdragon.authcore.casdoor.OidcExchangeClient;
import systems.snapdragon.authcore.casdoor.OidcTokens;
import systems.snapdragon.authcore.config.SessionCookieService;

/**
 * Casdoor OIDC browser-PKCE callback — the login leg owned by user-bff (so the browser
 * only ever holds the opaque {@code bff_} session, never a JWT). login-ui owns
 * client-side PKCE: it stores {@code state} + {@code verifier} in sessionStorage,
 * redirects to Casdoor, intercepts the redirect at {@code /login/callback}, validates
 * {@code state} from sessionStorage, then POSTs {@code {code, codeVerifier, redirectUri}}
 * as JSON to {@code POST /bff/auth/callback} here. The BFF:
 *
 * <ol>
 *   <li>EXCHANGE the {@code code} for tokens via auth-core's {@link OidcExchangeClient}
 *       (PKCE S256: the {@code codeVerifier} proves the browser made the original request
 *       — received directly in the POST body);</li>
 *   <li>PROVISION the account + mint the opaque {@code bff_} session via the
 *       {@link AdminBffInternalClient} (admin-bff owns those tables);</li>
 *   <li>CUSTODY-STAMP the exchanged tokens: AES-256-GCM-encrypt the access + refresh
 *       tokens with {@link BffCustodyCipher} HERE and hand only the ciphertext to
 *       admin-bff (which writes its own bff_session columns — user-bff never writes that
 *       DB);</li>
 *   <li>MINT the {@code bff_} cookie via {@link SessionCookieService} (only when
 *       {@code app.session.cookie.enabled}) and return 200 OK with
 *       {@link CallbackResult} — the non-secret routing hints the browser needs to
 *       decide where to navigate (registrationComplete flag + status).</li>
 * </ol>
 *
 * <p>SHIPS DARK: when {@code app.bff.oidc.enabled=false} (the default) auth-core's
 * {@code OidcExchangeConfig} contributes NO {@code OidcExchangeClient} bean, so the
 * {@link ObjectProvider} resolves to nothing and every callback is 503 — no exchange,
 * no internal call, no cookie. The OIDC token values are NEVER put in the response body
 * or logged; only the opaque {@code bff_} session crosses back to the browser.
 */
@Tag(name = "OIDC login callback", description =
        "Casdoor OIDC browser-PKCE callback. Ships dark behind app.bff.oidc.enabled; 503 when disabled.")
@RestController
@RequestMapping("/bff/auth")
public class OidcCallbackController {

    private static final Logger log = LoggerFactory.getLogger(OidcCallbackController.class);

    /** POST body from the login-ui's browser-side PKCE callback handoff. */
    public record OidcCallbackRequest(String code, String codeVerifier, String redirectUri) {}

    /** The non-secret routing hints the callback-completing browser needs. NEVER a JWT or token. */
    public record CallbackResult(boolean registrationComplete, String status) {}

    /** Intermediate result carrying both the opaque session token and the account metadata. */
    private record ProvisionResult(String bffToken, boolean registrationComplete) {}

    /** Absent (no bean) when app.bff.oidc.enabled=false — then every callback 503s. */
    private final ObjectProvider<OidcExchangeClient> exchangeClient;
    private final AdminBffInternalClient adminBff;
    private final BffCustodyCipher custody;
    private final SessionCookieService cookies;
    private final String defaultRedirectUri;

    public OidcCallbackController(ObjectProvider<OidcExchangeClient> exchangeClient,
                                  AdminBffInternalClient adminBff,
                                  BffCustodyCipher custody,
                                  SessionCookieService cookies,
                                  @Value("${app.bff.oidc.redirect-uri:https://snapdragon.systems/login/callback}")
                                  String defaultRedirectUri) {
        this.exchangeClient = exchangeClient;
        this.adminBff = adminBff;
        this.custody = custody;
        this.cookies = cookies;
        this.defaultRedirectUri = defaultRedirectUri;
    }

    @Operation(summary = "Casdoor OIDC callback: browser-PKCE handoff. Exchange code, "
            + "provision account+session via admin-bff, set the bff_ cookie. 200+body on success. "
            + "503 when the OIDC surface is dark.")
    @PostMapping("/callback")
    public Mono<ResponseEntity<CallbackResult>> callback(@RequestBody OidcCallbackRequest body,
                                                         ServerWebExchange exchange) {
        OidcExchangeClient client = exchangeClient.getIfAvailable();
        if (client == null) {
            // SHIPS-DARK: no exchange client bean → OIDC surface disabled.
            return Mono.error(new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,
                    "OIDC login is not enabled (app.bff.oidc.enabled=false)"));
        }
        // Fail-closed: enabled but no custody key → never store a plaintext token.
        if (!custody.isAvailable()) {
            return Mono.error(new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,
                    "OIDC custody cipher is unavailable (app.bff.custody-key blank) — refusing login"));
        }
        String redirectUri = (body.redirectUri() == null || body.redirectUri().isBlank())
                ? defaultRedirectUri : body.redirectUri();

        // Exchange code → tokens, provision account + session, custody-stamp, mint cookie.
        return client.exchangeCode(body.code(), body.codeVerifier(), redirectUri)
                .flatMap(this::provisionAndStamp)
                .flatMap(result -> completeWithBody(exchange, result));
    }

    /**
     * Provision the account, mint the opaque {@code bff_} session, and custody-stamp the
     * exchanged tokens onto it — yielding a {@link ProvisionResult} with the opaque session
     * token and the account's {@code registrationComplete} flag.
     */
    private Mono<ProvisionResult> provisionAndStamp(OidcTokens tokens) {
        // Ensure the account exists (admin-bff owns the account/allowlist tables).
        return adminBff.ensureAccount("casdoor", subjectOf(tokens))
                // Mint the opaque bff_ session row for that account, then stamp custody.
                .flatMap(account -> adminBff.createSession(account.id())
                        // AES-GCM-stamp the tokens; yield the session token + account flags.
                        .flatMap(session -> stamp(session.token(), tokens)
                                .thenReturn(new ProvisionResult(session.token(), account.registrationComplete()))));
    }

    /**
     * Set the bff_ session cookie (when app.session.cookie.enabled) and return 200 OK with
     * {@link CallbackResult} — the non-secret routing hints the browser needs. The opaque
     * session token appears ONLY in the Set-Cookie header, NEVER in the body.
     */
    private Mono<ResponseEntity<CallbackResult>> completeWithBody(ServerWebExchange exchange,
                                                                   ProvisionResult result) {
        if (cookies.enabled()) {
            // Mint the httpOnly bff_ session cookie with the opaque token.
            ResponseCookie cookie = cookies.mint(exchange.getRequest(), result.bffToken());
            exchange.getResponse().addCookie(cookie);
        }
        // "active": the BFF does not (yet) evaluate suspension here; the gateway's
        // BffSessionAuthFilter enforces it on every subsequent request.
        return Mono.just(ResponseEntity.ok(new CallbackResult(result.registrationComplete(), "active")));
    }

    /**
     * AES-256-GCM-encrypt the exchanged access + refresh tokens, then hand ONLY the
     * ciphertext to admin-bff to stamp onto its bff_session row. The plaintext tokens
     * never leave this method (never logged, never in a response body).
     */
    private Mono<Void> stamp(String bffToken, OidcTokens tokens) {
        String encAccess = custody.encrypt(tokens.accessToken());
        String encRefresh = tokens.refreshToken() == null ? null : custody.encrypt(tokens.refreshToken());
        return adminBff.stampCustody(bffToken, encAccess, encRefresh, tokens.expiresInSeconds());
    }

    /** Derive the account handle from the exchanged tokens. The id_token's subject is
     *  the stable Casdoor identity; admin-bff resolves/creates the account from it. */
    private static String subjectOf(OidcTokens tokens) {
        // The opaque id_token is passed through to admin-bff's ensure/allowlist contract
        // (#112) verbatim; admin-bff validates + extracts the subject server-side so the
        // login leg never has to parse/trust a token claim locally.
        return tokens.idToken();
    }
}
