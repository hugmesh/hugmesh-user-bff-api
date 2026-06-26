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
 * D6 Matrix BFF-proxy: forwards {@code /bff/user/matrix/**} to the {@code tuwunel-proxy
 * :4443} mTLS sidecar with the caller's homeserver-NATIVE token injected (the inbound
 * Casdoor bearer is stripped). Owner is resolved from the VALIDATED JWT subject — NEVER
 * a body/path field — so a caller can only ever use THEIR OWN custody token (the
 * cross-user isolation keystone is the owner-scoped custody load).
 *
 * <p>{@code @PreAuthorize hasRole('MATRIX')} mirrors today's provision gate, on top of
 * the {@code ROLE_USER} security floor. Streaming/long-poll
 * ({@code /_matrix/client/v3/sync}) passes through verbatim via {@link HsReverseProxy}.
 *
 * <p>LIVE BY DEFAULT ({@code app.hs-token.enabled} now defaults true): this proxy is the
 * ONLY homeserver path now that the browser holds no Matrix access token. Every method
 * still 503s when {@code app.hs-token.enabled=false} OR the custody cipher key is unset
 * (fail-closed) — there is no browser-token fallback.
 */
@Tag(name = "Matrix proxy (D6)", description = "Owner-scoped Matrix reverse-proxy; injects the server-held homeserver-native token. Live by default behind app.hs-token.enabled.")
@RestController
@RequestMapping("/bff/user/matrix")
@PreAuthorize("hasRole('MATRIX')")
public class MatrixProxyController {

    private static final String PREFIX = "/bff/user/matrix";

    private final boolean enabled;
    private final HsTokenCustody custody;
    private final ServiceTokenBroker broker;
    private final HsReverseProxy proxy;

    public MatrixProxyController(
            @Value("${app.hs-token.enabled:false}") boolean enabled,
            HsTokenCustody custody,
            ServiceTokenBroker broker,
            @Qualifier("matrixProxyWebClient") WebClient matrixProxyWebClient) {
        this.enabled = enabled;
        this.custody = custody;
        this.broker = broker;
        this.proxy = new HsReverseProxy(matrixProxyWebClient);
    }

    @Operation(summary = "Reverse-proxy any Matrix client-API call with the server-held native token (owner = JWT subject). 503 when the feature is dark.")
    @RequestMapping("/**")
    public Mono<Void> proxy(@AuthenticationPrincipal Jwt jwt, ServerWebExchange exchange) {
        if (!enabled || !custody.cipherAvailable()) {
            // Fail-closed: feature off (or no custody key) → 503. There is NO
            // browser-token fallback — the browser holds no homeserver token.
            return Mono.error(new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,
                    "Matrix BFF-proxy is not enabled (app.hs-token.enabled=false)"));
        }
        String owner = jwt.getSubject();
        String localpart = localpart(jwt);
        String upstreamPath = upstreamPath(exchange);

        Mono<String> load = custody.loadAccessToken(owner, HsServiceTokenRow.PLATFORM_MATRIX);
        Mono<String> remint = broker.mintMatrix(owner, localpart).map(MintedToken::accessToken);
        return proxy.forward(exchange, upstreamPath, load, remint);
    }

    /** The homeserver-native path = the request path with the {@code /bff/user/matrix}
     *  prefix removed (so {@code /bff/user/matrix/_matrix/client/v3/sync} →
     *  {@code /_matrix/client/v3/sync}). */
    private static String upstreamPath(ServerWebExchange exchange) {
        String path = exchange.getRequest().getPath().value();
        String rest = path.length() > PREFIX.length() ? path.substring(PREFIX.length()) : "/";
        return rest.isEmpty() ? "/" : rest;
    }

    /** The caller's homeserver localpart (Casdoor {@code preferred_username}; subject
     *  fallback) — used only for the re-mint leg, never from a request field. */
    private static String localpart(Jwt jwt) {
        String pu = jwt.getClaimAsString("preferred_username");
        return (pu == null || pu.isBlank()) ? jwt.getSubject() : pu;
    }
}
