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
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import systems.snapdragon.userbff.auth.CanonicalIdentityResolver;

/**
 * D6 Mastodon BFF-proxy: forwards {@code /bff/user/mastodon/**} to the {@code akkoma-proxy
 * :4443} mTLS sidecar with the caller's homeserver-NATIVE token injected (the inbound
 * Casdoor bearer is stripped). Owner is resolved from the VALIDATED JWT subject -- NEVER
 * a body/path field -- so a caller can only ever use THEIR OWN custody token.
 *
 * <p>{@code @PreAuthorize hasRole('MASTODON')} mirrors today's provision gate, on top of
 * the {@code ROLE_USER} security floor. Streaming ({@code /api/v1/streaming/**}) passes
 * through verbatim via {@link HsReverseProxy}.
 *
 * <p>LIVE BY DEFAULT ({@code app.hs-token.enabled} now defaults true): this proxy is the
 * ONLY homeserver path now that the browser holds no Mastodon access token. Every method
 * still 503s when {@code app.hs-token.enabled=false} OR the custody cipher key is unset
 * (fail-closed) -- there is no browser-token fallback.
 *
 * <p>The re-mint leg's localpart is resolved by the shared {@link CanonicalIdentityResolver}
 * (claim-first from the {@code bff_}-session synthetic Jwt's {@code mastodon_localpart}, else
 * the caller's OWN {@code casdoor:<subject>} account's persisted Mastodon fold -- NEVER a raw
 * cross-namespace guess nor a client-side re-fold of the Matrix localpart), failing closed
 * when the caller's own persisted localpart cannot be established.
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
    private final CanonicalIdentityResolver identity;

    public MastodonProxyController(
            @Value("${app.hs-token.enabled:false}") boolean enabled,
            HsTokenCustody custody,
            ServiceTokenBroker broker,
            @Qualifier("mastodonProxyWebClient") WebClient mastodonProxyWebClient,
            CanonicalIdentityResolver identity) {
        this.enabled = enabled;
        this.custody = custody;
        this.broker = broker;
        this.proxy = new HsReverseProxy(mastodonProxyWebClient);
        this.identity = identity;
    }

    @Operation(summary = "Reverse-proxy any Mastodon API call with the server-held native token (owner = JWT subject). 503 when the feature is dark.")
    @RequestMapping("/**")
    public Mono<Void> proxy(@AuthenticationPrincipal Jwt jwt, ServerWebExchange exchange) {
        if (!enabled || !custody.cipherAvailable()) {
            // Fail-closed: feature off (or no custody key) -> 503. There is NO
            // browser-token fallback -- the browser holds no homeserver token.
            return Mono.error(new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,
                    "Mastodon BFF-proxy is not enabled (app.hs-token.enabled=false)"));
        }
        String owner = jwt.getSubject();
        String upstreamPath = upstreamPath(exchange);

        Mono<String> load = custody.loadAccessToken(owner, HsServiceTokenRow.PLATFORM_MASTODON);
        // identity.mastodonLocalpart(jwt) is a Mono (may hop to admin-bff over the internal
        // surface) -- composed INTO the lazy remint chain rather than resolved eagerly, so the
        // own-account lookup only ever fires when a mint is actually needed. Fails CLOSED (no
        // mint) if the caller's OWN persisted Mastodon localpart cannot be resolved.
        Mono<String> remint = identity.mastodonLocalpart(jwt).flatMap(lp -> broker.mintMastodon(owner, lp))
                .map(MintedToken::accessToken);
        return proxy.forward(exchange, upstreamPath, load, remint);
    }

    private static String upstreamPath(ServerWebExchange exchange) {
        String path = exchange.getRequest().getPath().value();
        String rest = path.length() > PREFIX.length() ? path.substring(PREFIX.length()) : "/";
        return rest.isEmpty() ? "/" : rest;
    }
}
