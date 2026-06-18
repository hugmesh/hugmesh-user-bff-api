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
 * <p>SHIPS DARK: every method 503s when {@code app.hs-token.enabled=false} (default) OR
 * the custody cipher key is unset — the legacy admin-bff {@code /bff/provision/*}
 * browser-token path stays the live fallback (NOT removed here; PR5/UI is out of scope).
 */
@Tag(name = "Mastodon proxy (D6)", description = "Owner-scoped Mastodon reverse-proxy; injects the server-held homeserver-native token. Ships dark behind app.hs-token.enabled.")
@RestController
@RequestMapping("/bff/user/mastodon")
@PreAuthorize("hasRole('MASTODON')")
public class MastodonProxyController {

    private static final String PREFIX = "/bff/user/mastodon";

    private final boolean enabled;
    private final HsTokenCustody custody;
    private final ServiceTokenBroker broker;
    private final HsReverseProxy proxy;

    public MastodonProxyController(
            @Value("${app.hs-token.enabled:false}") boolean enabled,
            HsTokenCustody custody,
            ServiceTokenBroker broker,
            @Qualifier("mastodonProxyWebClient") WebClient mastodonProxyWebClient) {
        this.enabled = enabled;
        this.custody = custody;
        this.broker = broker;
        this.proxy = new HsReverseProxy(mastodonProxyWebClient, HsServiceTokenRow.PLATFORM_MASTODON);
    }

    @Operation(summary = "Reverse-proxy any Mastodon API call with the server-held native token (owner = JWT subject). 503 when the feature is dark.")
    @RequestMapping("/**")
    public Mono<Void> proxy(@AuthenticationPrincipal Jwt jwt, ServerWebExchange exchange) {
        if (!enabled || !custody.cipherAvailable()) {
            // SHIPS-DARK: feature off (or no custody key) → 503; the legacy
            // /bff/provision/* browser-token path is the live fallback.
            return Mono.error(new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,
                    "Mastodon BFF-proxy is not enabled (app.hs-token.enabled=false)"));
        }
        String owner = jwt.getSubject();
        String localpart = localpart(jwt);
        String upstreamPath = upstreamPath(exchange);

        Mono<String> load = custody.loadAccessToken(owner, HsServiceTokenRow.PLATFORM_MASTODON);
        Mono<String> remint = broker.mintMastodon(owner, localpart).map(MintedToken::accessToken);
        return proxy.forward(exchange, upstreamPath, load, remint);
    }

    private static String upstreamPath(ServerWebExchange exchange) {
        String path = exchange.getRequest().getPath().value();
        String rest = path.length() > PREFIX.length() ? path.substring(PREFIX.length()) : "/";
        return rest.isEmpty() ? "/" : rest;
    }

    private static String localpart(Jwt jwt) {
        String pu = jwt.getClaimAsString("preferred_username");
        return (pu == null || pu.isBlank()) ? jwt.getSubject() : pu;
    }
}
