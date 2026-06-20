package systems.snapdragon.userbff.hsproxy;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.Locale;
import java.util.Set;
import java.util.function.BiFunction;

/**
 * The reactive reverse-proxy ENGINE shared by the Matrix + Mastodon controllers. For one
 * inbound {@code /bff/user/{platform}/**} request it:
 *
 * <ol>
 *   <li>resolves the homeserver-native token for the owner (the controller passes a
 *       loader keyed on the VALIDATED JWT subject — never a body field);</li>
 *   <li>STRIPS the inbound Casdoor bearer and any hop-by-hop headers, INJECTS the
 *       decrypted homeserver-native token as {@code Authorization: Bearer <native>};</li>
 *   <li>forwards the method + remaining path + query + body over the supplied mTLS
 *       {@link WebClient} (pointed at {@code *-proxy:4443}) as a STREAMING
 *       {@code Flux<DataBuffer>} body (no buffering, no read-timeout cap), propagating
 *       the upstream status, headers and body verbatim — so long-poll/SSE/WS-upgrade
 *       ({@code /_matrix/client/v3/sync}, {@code /api/v1/streaming/**}) pass through;</li>
 *   <li>on an upstream {@code 401}, re-mints once via the broker, re-encrypts+upserts the
 *       custody row, rewrites the gateway revocation hash, and RETRIES once with the
 *       fresh token; a second {@code 401} (or a failed re-mint) is a fail-closed
 *       {@code 401} to the caller.</li>
 * </ol>
 *
 * <p>The native token is NEVER returned to the caller (it only ever rides the OUTBOUND
 * Authorization header) and NEVER logged.
 */
public class HsReverseProxy {

    private static final Logger log = LoggerFactory.getLogger(HsReverseProxy.class);

    /** Hop-by-hop + identity headers we never forward inbound→upstream. The inbound
     *  Authorization (the Casdoor bearer) is dropped here — the native token replaces it. */
    private static final Set<String> STRIP_REQUEST_HEADERS = Set.of(
            HttpHeaders.AUTHORIZATION.toLowerCase(Locale.ROOT),
            HttpHeaders.HOST.toLowerCase(Locale.ROOT),
            "cookie",
            "content-length",
            "transfer-encoding",
            "keep-alive",
            "proxy-authorization",
            "te",
            "trailer");

    /** Hop-by-hop headers we never copy back upstream→caller (let the container set them). */
    private static final Set<String> STRIP_RESPONSE_HEADERS = Set.of(
            "transfer-encoding",
            "connection",
            "keep-alive",
            "content-length");

    private static final Set<HttpMethod> BODY_METHODS =
            Set.of(HttpMethod.POST, HttpMethod.PUT, HttpMethod.PATCH, HttpMethod.DELETE);

    private final WebClient upstream;
    private final String platform;

    public HsReverseProxy(WebClient upstream, String platform) {
        this.upstream = upstream;
        this.platform = platform;
    }

    /**
     * Forward one exchange. {@code upstreamPath} is the homeserver-native path (the
     * {@code /bff/user/{platform}} prefix already stripped). {@code loadToken} yields the
     * decrypted native token (fail-closed empty → 401). {@code remint} re-mints on a 401
     * and yields the fresh native token (empty → fail-closed 401).
     */
    public Mono<Void> forward(ServerWebExchange exchange, String upstreamPath,
                              Mono<String> loadToken, Mono<String> remint) {
        ServerHttpRequest req = exchange.getRequest();
        String query = req.getURI().getRawQuery();
        String fullPath = (query == null || query.isBlank()) ? upstreamPath : upstreamPath + "?" + query;

        return loadToken
                .switchIfEmpty(Mono.error(unauthorized("no custody token for this user/platform")))
                .flatMap(nativeToken -> exchangeAndRelay(exchange, fullPath, nativeToken)
                        .flatMap(relayed -> {
                            if (Boolean.TRUE.equals(relayed)) {
                                return Mono.empty();
                            }
                            // Refresh-on-401: re-mint once, retry once, then fail closed.
                            return remint
                                    .switchIfEmpty(Mono.error(unauthorized("re-mint failed (fail-closed)")))
                                    .flatMap(fresh -> exchangeAndRelay(exchange, fullPath, fresh))
                                    .flatMap(retryRelayed -> Boolean.TRUE.equals(retryRelayed)
                                            ? Mono.empty()
                                            : Mono.error(unauthorized("upstream 401 after re-mint (fail-closed)")));
                        }));
    }

    /**
     * One upstream call with the native token injected. The response body is consumed
     * INSIDE the {@code exchangeToMono} callback (the documented WebClient contract — a
     * body left unconsumed past the callback is released, dropping the stream):
     * <ul>
     *   <li>on a non-401 status → STREAM the upstream body verbatim to the caller's
     *       response and complete with {@code true} (relayed);</li>
     *   <li>on a {@code 401} → release the body and complete with {@code false} so the
     *       caller drives the refresh-on-401 retry.</li>
     * </ul>
     */
    private Mono<Boolean> exchangeAndRelay(ServerWebExchange exchange, String fullPath, String nativeToken) {
        ServerHttpRequest req = exchange.getRequest();
        HttpMethod method = req.getMethod();

        // WebClient.uri(String) keeps the already-encoded path + query verbatim.
        WebClient.RequestBodySpec built = upstream
                .method(method)
                .uri(fullPath)
                .headers(h -> copyRequestHeaders(req.getHeaders(), h, nativeToken));

        WebClient.RequestHeadersSpec<?> headersSpec;
        if (BODY_METHODS.contains(method)) {
            // STREAMING request body passthrough (no buffering of uploads).
            Flux<DataBuffer> body = req.getBody();
            headersSpec = built.body((outbound, ctx) -> outbound.writeWith(body));
        } else {
            headersSpec = built;
        }
        return headersSpec.exchangeToMono(resp -> {
            if (resp.statusCode().value() == HttpStatus.UNAUTHORIZED.value()) {
                // Let the caller re-mint + retry; release this body first.
                return resp.releaseBody().thenReturn(Boolean.FALSE);
            }
            ServerHttpResponse out = exchange.getResponse();
            out.setStatusCode(resp.statusCode());
            copyResponseHeaders(resp.headers().asHttpHeaders(), out.getHeaders());
            // STREAM the upstream body verbatim (no buffering, no read-timeout cap) —
            // long-poll/SSE/WS-upgrade pass through. Consumed inside the callback.
            return out.writeWith(resp.bodyToFlux(DataBuffer.class)).thenReturn(Boolean.TRUE);
        });
    }

    private void copyRequestHeaders(HttpHeaders in, HttpHeaders out, String nativeToken) {
        in.forEach((name, values) -> {
            if (!STRIP_REQUEST_HEADERS.contains(name.toLowerCase(Locale.ROOT))) {
                out.put(name, values);
            }
        });
        // Inject the homeserver-native bearer (replaces the stripped Casdoor bearer).
        out.set(HttpHeaders.AUTHORIZATION, "Bearer " + nativeToken);
        // Propagate Connection: Upgrade for the WS/streaming sidecar leg.
        if (in.containsHeader(HttpHeaders.UPGRADE)) {
            out.put(HttpHeaders.UPGRADE, in.get(HttpHeaders.UPGRADE));
            out.set(HttpHeaders.CONNECTION, "Upgrade");
        }
    }

    private void copyResponseHeaders(HttpHeaders in, HttpHeaders out) {
        in.forEach((name, values) -> {
            if (!STRIP_RESPONSE_HEADERS.contains(name.toLowerCase(Locale.ROOT))) {
                out.put(name, values);
            }
        });
    }

    private static ResponseStatusException unauthorized(String reason) {
        return new ResponseStatusException(HttpStatus.UNAUTHORIZED, reason);
    }

    /** Functional shape for the controller's re-mint supplier (kept for readability). */
    public interface Reminter extends BiFunction<String, String, Mono<String>> {
    }
}
