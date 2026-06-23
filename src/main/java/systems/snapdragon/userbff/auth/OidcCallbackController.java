package systems.snapdragon.userbff.auth;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import systems.snapdragon.authcore.casdoor.BffCustodyCipher;
import systems.snapdragon.authcore.casdoor.OidcExchangeClient;
import systems.snapdragon.authcore.casdoor.OidcTokens;
import systems.snapdragon.authcore.config.SessionCookieService;

import java.net.URI;

/**
 * Casdoor OIDC redirect-callback — the relocation of the login leg from admin-bff to
 * user-bff (so user-bff OWNS login/OIDC and the browser only ever holds the opaque
 * {@code bff_} session, never a JWT). Handles {@code GET /bff/auth/callback?code=&state=}:
 *
 * <ol>
 *   <li>VALIDATE {@code state} against the server-side {@link OidcPendingStore}
 *       (single-use; unknown/expired ⇒ fail closed 400) and recover the PKCE
 *       {@code verifier} + the per-flow {@code redirect_uri};</li>
 *   <li>EXCHANGE the {@code code} for tokens via auth-core's {@link OidcExchangeClient}
 *       (PKCE S256);</li>
 *   <li>PROVISION the account + mint the opaque {@code bff_} session via the
 *       {@link AdminBffInternalClient} (admin-bff owns those tables);</li>
 *   <li>CUSTODY-STAMP the exchanged tokens: AES-256-GCM-encrypt the access + refresh
 *       tokens with {@link BffCustodyCipher} HERE and hand only the ciphertext to
 *       admin-bff (which writes its own bff_session columns — user-bff never writes that
 *       DB);</li>
 *   <li>MINT the {@code bff_} cookie via {@link SessionCookieService} (only when
 *       {@code app.session.cookie.enabled}) and 302 the browser back to the UI.</li>
 * </ol>
 *
 * <p>SHIPS DARK: when {@code app.bff.oidc.enabled=false} (the default) auth-core's
 * {@code OidcExchangeConfig} contributes NO {@code OidcExchangeClient} bean, so the
 * {@link ObjectProvider} resolves to nothing and every callback is 503 — no exchange,
 * no internal call, no cookie. The OIDC token values are NEVER put in the response body
 * or logged; only the opaque {@code bff_} session crosses back to the browser.
 */
@Tag(name = "OIDC login callback", description =
        "Casdoor OIDC redirect callback. Ships dark behind app.bff.oidc.enabled; 503 when disabled.")
@RestController
@RequestMapping("/bff/auth")
public class OidcCallbackController {

    private static final Logger log = LoggerFactory.getLogger(OidcCallbackController.class);

    /** Absent (no bean) when app.bff.oidc.enabled=false — then every callback 503s. */
    private final ObjectProvider<OidcExchangeClient> exchangeClient;
    private final OidcPendingStore pending;
    private final AdminBffInternalClient adminBff;
    private final BffCustodyCipher custody;
    private final SessionCookieService cookies;
    private final String defaultRedirectUri;

    public OidcCallbackController(ObjectProvider<OidcExchangeClient> exchangeClient,
                                  OidcPendingStore pending,
                                  AdminBffInternalClient adminBff,
                                  BffCustodyCipher custody,
                                  SessionCookieService cookies,
                                  @Value("${app.bff.oidc.redirect-uri:https://snapdragon.systems/login/callback}")
                                  String defaultRedirectUri) {
        this.exchangeClient = exchangeClient;
        this.pending = pending;
        this.adminBff = adminBff;
        this.custody = custody;
        this.cookies = cookies;
        this.defaultRedirectUri = defaultRedirectUri;
    }

    @Operation(summary = "Casdoor OIDC callback: validate state, exchange code (PKCE), "
            + "provision account+session via admin-bff, mint the bff_ cookie, 302 to the UI. "
            + "503 when the OIDC surface is dark.")
    @GetMapping("/callback")
    public Mono<Void> callback(@RequestParam("code") String code,
                               @RequestParam("state") String state,
                               ServerWebExchange exchange) {
        OidcExchangeClient client = exchangeClient.getIfAvailable();
        if (client == null) {
            // SHIPS-DARK / fail-closed: no exchange client bean (app.bff.oidc.enabled=false).
            return Mono.error(new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,
                    "OIDC login is not enabled (app.bff.oidc.enabled=false)"));
        }
        // Fail-closed second invariant: enabled but no custody key ⇒ never store a
        // plaintext token. The boot guard already refuses this combination at startup;
        // re-assert here so a hot-reconfigured cipher can never silently degrade.
        if (!custody.isAvailable()) {
            return Mono.error(new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,
                    "OIDC custody cipher is unavailable (app.bff.custody-key blank) — refusing login"));
        }

        // 1) state is single-use: unknown/expired/replayed ⇒ reject (fail closed).
        OidcPendingStore.Pending flow = pending.consume(state).orElse(null);
        if (flow == null) {
            return Mono.error(new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "unknown, expired, or already-used login state"));
        }
        String redirectUri = (flow.redirectUri() == null || flow.redirectUri().isBlank())
                ? defaultRedirectUri : flow.redirectUri();

        // 2) PKCE code -> tokens. 3-5) provision account + session + custody-stamp (named
        // helper flattens the former 3-deep ensure/createSession/stamp ladder). 6) cookie.
        return client.exchangeCode(code, flow.verifier(), redirectUri)
                .flatMap(this::provisionAndStamp)
                .flatMap(bffToken -> completeRedirect(exchange, redirectUri, bffToken));
    }

    /**
     * Provision the account, mint the opaque {@code bff_} session, and custody-stamp the
     * exchanged tokens onto it — yielding the opaque session token. Extracted from {@link
     * #callback} so the former 3-deep {@code ensureAccount → createSession → stamp} nested
     * lambda ladder reads as a flat named chain (behaviour identical).
     */
    private Mono<String> provisionAndStamp(OidcTokens tokens) {
        // 3) ensure the account exists (admin-bff owns the account/allowlist tables).
        return adminBff.ensureAccount("casdoor", subjectOf(tokens))
                // 4) mint the opaque bff_ session row for that account.
                .flatMap(account -> adminBff.createSession(account.id()))
                // 5) AES-GCM-stamp the tokens onto the session, then yield its opaque token.
                .flatMap(session -> stamp(session.token(), tokens).thenReturn(session.token()));
    }

    /**
     * Mint the opaque {@code bff_} cookie (only when {@code app.session.cookie.enabled})
     * and 302 the browser back to the UI. Extracted from {@link #callback} so the final
     * response-writing leg is a named step rather than a trailing inline lambda.
     */
    private Mono<Void> completeRedirect(ServerWebExchange exchange, String redirectUri, String bffToken) {
        exchange.getResponse().setStatusCode(HttpStatus.FOUND);
        exchange.getResponse().getHeaders().setLocation(URI.create(redirectUri));
        if (cookies.enabled()) {
            ResponseCookie cookie = cookies.mint(exchange.getRequest(), bffToken);
            exchange.getResponse().addCookie(cookie);
        }
        return exchange.getResponse().setComplete();
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
