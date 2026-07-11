package systems.snapdragon.userbff.hsproxy;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import systems.snapdragon.userbff.auth.AdminBffInternalClient;

import java.util.Locale;

/**
 * D6 Mastodon BFF-proxy: forwards {@code /bff/user/mastodon/**} to the {@code akkoma-proxy
 * :4443} mTLS sidecar with the caller's homeserver-NATIVE token injected (the inbound
 * Casdoor bearer is stripped). Owner is resolved from the VALIDATED JWT subject — NEVER
 * a body/path field — so a caller can only ever use THEIR OWN custody token.
 *
 * <p>{@code @PreAuthorize hasRole('MASTODON')} mirrors today's provision gate, on top of
 * the {@code ROLE_USER} security floor. Streaming ({@code /api/v1/streaming/**}) passes
 * through verbatim via {@link HsReverseProxy}.
 *
 * <p>LIVE BY DEFAULT ({@code app.hs-token.enabled} now defaults true): this proxy is the
 * ONLY homeserver path now that the browser holds no Mastodon access token. Every method
 * still 503s when {@code app.hs-token.enabled=false} OR the custody cipher key is unset
 * (fail-closed) — there is no browser-token fallback.
 */
@Tag(name = "Mastodon proxy (D6)", description = "Owner-scoped Mastodon reverse-proxy; injects the server-held homeserver-native token. Live by default behind app.hs-token.enabled.")
@RestController
@RequestMapping("/bff/user/mastodon")
@PreAuthorize("hasRole('MASTODON')")
public class MastodonProxyController {

    private static final String PREFIX = "/bff/user/mastodon";

    private final boolean enabled;
    private final HsTokenCustody custody;
    private final ServiceTokenBroker broker;
    private final HsReverseProxy proxy;
    private final AdminBffInternalClient adminBff;

    public MastodonProxyController(
            @Value("${app.hs-token.enabled:false}") boolean enabled,
            HsTokenCustody custody,
            ServiceTokenBroker broker,
            @Qualifier("mastodonProxyWebClient") WebClient mastodonProxyWebClient,
            AdminBffInternalClient adminBff) {
        this.enabled = enabled;
        this.custody = custody;
        this.broker = broker;
        this.proxy = new HsReverseProxy(mastodonProxyWebClient);
        this.adminBff = adminBff;
    }

    @Operation(summary = "Reverse-proxy any Mastodon API call with the server-held native token (owner = JWT subject). 503 when the feature is dark.")
    @RequestMapping("/**")
    public Mono<Void> proxy(@AuthenticationPrincipal Jwt jwt, ServerWebExchange exchange) {
        if (!enabled || !custody.cipherAvailable()) {
            // Fail-closed: feature off (or no custody key) → 503. There is NO
            // browser-token fallback — the browser holds no homeserver token.
            return Mono.error(new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,
                    "Mastodon BFF-proxy is not enabled (app.hs-token.enabled=false)"));
        }
        String owner = jwt.getSubject();
        String upstreamPath = upstreamPath(exchange);

        Mono<String> load = custody.loadAccessToken(owner, HsServiceTokenRow.PLATFORM_MASTODON);
        // localpart(jwt) is a Mono (may hop to admin-bff over the internal surface) —
        // composed INTO the lazy remint chain rather than resolved eagerly, so the
        // account-takeover-by-collision lookup only ever fires when a mint is actually
        // needed (first-use / 401-retry — see HsReverseProxy#forward), exactly matching
        // this Mono's existing on-demand-only subscription semantics.
        Mono<String> remint = localpart(jwt).flatMap(lp -> broker.mintMastodon(owner, lp))
                .map(MintedToken::accessToken);
        return proxy.forward(exchange, upstreamPath, load, remint);
    }

    private static String upstreamPath(ServerWebExchange exchange) {
        String path = exchange.getRequest().getPath().value();
        String rest = path.length() > PREFIX.length() ? path.substring(PREFIX.length()) : "/";
        return rest.isEmpty() ? "/" : rest;
    }

    /**
     * The caller's homeserver localpart — used only for the re-mint leg, never from a
     * request field. See {@code MatrixProxyController.localpart}'s doc (identical logic,
     * byte-for-byte) for the account-takeover-by-collision fix rationale, including the
     * gap-1 close: the FALLBACK branch (no synthetic {@code localpart} claim — a real,
     * externally-issued Casdoor JWT presented directly to this
     * {@code @PreAuthorize hasRole('MASTODON')} route, which {@code SecurityConfig} still
     * fully validates via {@code o.jwt(...)} against the live issuer-uri) now resolves the
     * SAME persisted, collision-checked value via a real internal admin-bff lookup instead
     * of re-deriving an unchecked candidate, FAIL CLOSED on any lookup failure.
     */
    private Mono<String> localpart(Jwt jwt) {
        String canonical = jwt.getClaimAsString("localpart");
        if (canonical != null && !canonical.isBlank()) {
            return Mono.just(canonical);
        }
        return resolveCanonicalLocalpart(jwt);
    }

    /**
     * Resolve the canonical, persisted, collision-checked localpart for a REAL Casdoor JWT
     * that carries no synthetic-session {@code localpart} claim. Byte-for-byte identical to
     * {@code MatrixProxyController}'s copy (this org's established duplication pattern for
     * the two D6 proxy controllers, e.g. {@code upstreamPath}/{@code PREFIX} above) — see
     * its doc for the full rationale.
     */
    private Mono<String> resolveCanonicalLocalpart(Jwt jwt) {
        String email = jwt.getClaimAsString("email");
        String pu = jwt.getClaimAsString("preferred_username");
        Mono<AdminBffInternalClient.AccountView> byEmail = (email != null && !email.isBlank())
                ? adminBff.getAccount(idFor("google", email))
                        .onErrorResume(WebClientResponseException.NotFound.class, e -> Mono.empty())
                : Mono.empty();
        Mono<AdminBffInternalClient.AccountView> byUsername = (pu != null && !pu.isBlank())
                ? adminBff.getAccount(idFor("discord", pu))
                        .onErrorResume(WebClientResponseException.NotFound.class, e -> Mono.empty())
                : Mono.empty();
        return byEmail.switchIfEmpty(byUsername)
                .switchIfEmpty(Mono.error(new ResponseStatusException(HttpStatus.UNAUTHORIZED,
                        "no registered account for this token's identity claims "
                                + "(fail-closed homeserver-localpart resolution)")))
                .flatMap(a -> {
                    String lp = a.localpart();
                    return (lp == null || lp.isBlank())
                            ? Mono.error(new ResponseStatusException(HttpStatus.CONFLICT,
                                    "account has no persisted homeserver localpart yet "
                                            + "(fail-closed — will not re-derive an unchecked candidate)"))
                            : Mono.just(lp);
                });
    }

    /** Mirrors {@code AccountStore.idFor(provider, handle) = provider + ":" +
     *  handle.toLowerCase()} — the SAME textual convention {@code SessionsService
     *  .accountIdFromJwt} already documents+replicates in this repo rather than taking a
     *  compile dependency on the exact auth-core method for what is a stable, one-line
     *  identity-string format. */
    private static String idFor(String provider, String handle) {
        return provider + ":" + handle.toLowerCase(Locale.ROOT);
    }
}
