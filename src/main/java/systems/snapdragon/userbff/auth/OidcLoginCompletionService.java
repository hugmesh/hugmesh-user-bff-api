package systems.snapdragon.userbff.auth;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import systems.snapdragon.authcore.casdoor.BffCustodyCipher;
import systems.snapdragon.authcore.casdoor.OidcExchangeClient;
import systems.snapdragon.authcore.casdoor.OidcTokens;
import systems.snapdragon.authcore.config.SessionCookieService;

/**
 * The ONE shared login-completion path: EXCHANGE a Casdoor authorization {@code code} for
 * tokens, PROVISION the account + opaque {@code bff_} session via admin-bff, CUSTODY-STAMP
 * the exchanged tokens (AES-256-GCM), and MINT the {@code bff_} cookie. The sole caller is
 * {@link SsoAuthController} — the native {@code POST /bff/login}, where this BFF owns the
 * PKCE verifier (generated server-side alongside the credential check) and feeds the
 * resulting {@code code} into this single method, so the security-critical crypto/session
 * logic lives in exactly one place.
 *
 * <p>INVARIANT: the exchanged access/refresh/id tokens NEVER leave this service in a
 * response — only the opaque {@code bff_} session token is minted, and only into the
 * {@code Set-Cookie} header (never the body). Fail-closed: with no {@link OidcExchangeClient}
 * bean (surface dark) or no custody key, {@link #complete} 503s before any exchange.
 */
@Service
public class OidcLoginCompletionService {

    /** The non-secret outcome of a completed login — never a token. */
    public record Completed(boolean registrationComplete, String status) {}

    /** Intermediate: the opaque session token + the account's registration flag. */
    private record ProvisionResult(String bffToken, boolean registrationComplete) {}

    /** Absent (no bean) when app.bff.oidc.enabled=false — then every completion 503s. */
    private final ObjectProvider<OidcExchangeClient> exchangeClient;
    private final AdminBffInternalClient adminBff;
    private final BffCustodyCipher custody;
    private final SessionCookieService cookies;

    public OidcLoginCompletionService(ObjectProvider<OidcExchangeClient> exchangeClient,
                                      AdminBffInternalClient adminBff,
                                      BffCustodyCipher custody,
                                      SessionCookieService cookies) {
        this.exchangeClient = exchangeClient;
        this.adminBff = adminBff;
        this.custody = custody;
        this.cookies = cookies;
    }

    /**
     * Exchange {@code code} (with the matching PKCE {@code codeVerifier} + {@code redirectUri}),
     * provision the account + session, custody-stamp the tokens, mint the {@code bff_} cookie
     * onto {@code exchange}, and yield the non-secret {@link Completed} routing hints. Fail-closed
     * 503 when the OIDC surface is dark or the custody key is blank.
     */
    public Mono<Completed> complete(String code, String codeVerifier, String redirectUri,
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
        return client.exchangeCode(code, codeVerifier, redirectUri)
                .flatMap(this::provisionAndStamp)
                .map(result -> {
                    mintCookie(exchange, result.bffToken());
                    // "active": suspension is enforced by the gateway's BffSessionAuthFilter
                    // on every subsequent request, not evaluated here.
                    return new Completed(result.registrationComplete(), "active");
                });
    }

    /**
     * Provision the account, mint the opaque {@code bff_} session, and custody-stamp the
     * exchanged tokens onto it.
     */
    private Mono<ProvisionResult> provisionAndStamp(OidcTokens tokens) {
        return adminBff.ensureAccount("casdoor", subjectOf(tokens))
                .flatMap(account -> adminBff.createSession(account.id())
                        .flatMap(session -> stamp(session.token(), tokens)
                                .thenReturn(new ProvisionResult(session.token(), account.registrationComplete()))));
    }

    /** Set the {@code bff_} cookie (opaque token ONLY in the Set-Cookie header) when armed. */
    private void mintCookie(ServerWebExchange exchange, String bffToken) {
        if (cookies.enabled()) {
            ResponseCookie cookie = cookies.mint(exchange.getRequest(), bffToken);
            if (cookie != null) {
                exchange.getResponse().addCookie(cookie);
            }
        }
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

    /** The id_token's subject is the stable Casdoor identity; admin-bff resolves/creates the
     *  account from it (it validates + extracts the subject server-side). */
    private static String subjectOf(OidcTokens tokens) {
        return tokens.idToken();
    }
}
