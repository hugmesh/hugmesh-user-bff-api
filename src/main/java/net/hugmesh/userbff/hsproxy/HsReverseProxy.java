package net.hugmesh.userbff.hsproxy;

import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import net.hugmesh.commons.web.ApiException;

import java.net.URI;
import java.util.Locale;
import java.util.Set;
import java.util.function.BiFunction;

/**
 * The reactive reverse-proxy ENGINE shared by the Matrix + Mastodon controllers. For one
 * inbound {@code /bff/user/{platform}/**} request it:
 *
 * <ol>
 *   <li>resolves the homeserver-native token for the owner (the controller passes a
 *       loader keyed on the VALIDATED JWT subject — never a body field); when NO custody
 *       row exists yet (first use — nothing seeds custody at login time, for native login
 *       OR legacy OAuth), lazily mints one via the controller's broker mono instead of
 *       failing closed;</li>
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

    /** Hop-by-hop + identity headers we never forward inbound→upstream. The inbound
     *  Authorization (the Casdoor bearer) is dropped here — the native token replaces it.
     *  Forwarding metadata ({@code X-Forwarded-*}/{@code Forwarded}) is stripped too:
     *  this BFF is the client on the upstream leg, and relaying the caller's edge
     *  metadata both leaks it and breaks upstreams that trust it (mainline Mastodon's
     *  force_ssl 308s any request whose {@code X-Forwarded-Proto} isn't https — the
     *  WebClient bean asserts the correct value itself on a plain-HTTP leg, which a
     *  relayed inbound value would override). */
    private static final Set<String> STRIP_REQUEST_HEADERS = Set.of(
            HttpHeaders.AUTHORIZATION.toLowerCase(Locale.ROOT),
            HttpHeaders.HOST.toLowerCase(Locale.ROOT),
            "cookie",
            "content-length",
            "transfer-encoding",
            "keep-alive",
            "proxy-authorization",
            "te",
            "trailer",
            "forwarded",
            "x-forwarded-proto",
            "x-forwarded-for",
            "x-forwarded-host",
            "x-forwarded-port");

    /** Hop-by-hop headers we never copy back upstream→caller (let the container set them). */
    private static final Set<String> STRIP_RESPONSE_HEADERS = Set.of(
            "transfer-encoding",
            "connection",
            "keep-alive",
            "content-length");

    private static final Set<HttpMethod> BODY_METHODS =
            Set.of(HttpMethod.POST, HttpMethod.PUT, HttpMethod.PATCH, HttpMethod.DELETE);

    private final WebClient upstream;

    public HsReverseProxy(WebClient upstream) {
        this.upstream = upstream;
    }

    /**
     * Forward one exchange. {@code upstreamPath} is the homeserver-native path (the
     * {@code /bff/user/{platform}} prefix already stripped). {@code loadToken} yields the
     * decrypted native token; an EMPTY load (no custody row yet) triggers a FIRST-USE
     * lazy mint via {@code remint} — see {@link #firstUseMint}. {@code remint} also
     * re-mints on an upstream 401 and yields the fresh native token (empty → fail-closed
     * 401).
     *
     * <p>SSRF GUARD: {@code upstreamPath} MUST be a single-{@code '/'}-leading, same-host
     * RELATIVE path. A scheme-relative authority ({@code //evil.com/x}), a backslash
     * variant ({@code /\evil}, {@code \evil}) or an embedded scheme ({@code https://evil})
     * would override the mTLS WebClient's baseUrl host — leaking the decrypted homeserver
     * Bearer + the BFF mTLS client cert to an attacker host. We {@link #requireSafePath
     * reject such paths with 400} BEFORE any token is loaded or any upstream request is
     * built, and construct the upstream {@link URI} via {@link UriComponentsBuilder#fromPath
     * path-only} so an embedded authority can never override the host.
     */
    public Mono<Void> forward(ServerWebExchange exchange, String upstreamPath,
                              Mono<String> loadToken, Mono<String> remint) {
        // Fail-fast SSRF guard: validate the relative path BEFORE loading the token or
        // building the upstream request (so a hostile path never touches the mTLS leg).
        // Deferred into the reactive chain so a bad path surfaces as a 400 Mono.error
        // (never an unconsumed token / mTLS leg) regardless of the caller's wiring.
        return Mono.defer(() -> {
            requireSafePath(upstreamPath);

            ServerHttpRequest req = exchange.getRequest();
            String query = req.getURI().getRawQuery();
            // Build a path-ONLY relative URI: UriComponentsBuilder.fromPath() never parses
            // an authority, so even a path that somehow slipped the guard cannot set a host.
            // The request path value + raw query are already URL-encoded → build(true).
            URI relativeUpstream = UriComponentsBuilder.fromPath(upstreamPath)
                    .query(query == null || query.isBlank() ? null : query)
                    .build(true)
                    .toUri();
            String fullPath = relativeUpstream.toString();

            // Load the native token (first-use lazy mint on empty), forward the request,
            // and refresh-on-401 if needed.
            boolean bodyMethod = BODY_METHODS.contains(req.getMethod());
            return loadToken
                    .switchIfEmpty(Mono.defer(() -> firstUseMint(remint)))
                    .flatMap(nativeToken -> exchangeAndRelay(exchange, fullPath, nativeToken)
                            .flatMap(relayed -> handleRelayResult(relayed, exchange, fullPath, remint, bodyMethod)));
        });
    }

    /**
     * FIRST-USE lazy mint: no custody row exists for this owner/platform yet, so mint one
     * now instead of failing closed. Nothing seeds {@code hs_service_token} at login time
     * — the legacy OAuth flow relied on the same broker at provision/first-401 time, and
     * native login (the synthetic bff_-session principal) mints nothing at completion —
     * so before this fallback a native-login caller's FIRST hsproxy request died here with
     * "no custody token" even though the controller had a working mint wired up one
     * argument away (it was only ever fired on an upstream 401). Reusing the controller's
     * {@code remint} mono keeps the semantics identical to the 401 leg: mint + encrypt +
     * upsert keyed on the CURRENT validated JWT subject + gateway revocation-hash write —
     * so the row self-seeds under whichever subject shape the caller authenticated with
     * (native casdoor id or legacy provider id) and the next request takes the plain
     * custody-load path. Same pattern as {@code StickerPackRegistrationService}'s
     * mint-on-empty.
     *
     * <p>Failure posture: a mint that completes EMPTY is the same fail-closed 401 as the
     * old empty-custody error; a mint that ERRORS with its own status (e.g. the broker's
     * unconfigured-password 503) surfaces verbatim; any other failure (homeserver sidecar
     * unreachable/refusing) maps to 502 — the homeserver leg is down, which is neither the
     * caller's fault (4xx) nor this service's (500).
     */
    private static Mono<String> firstUseMint(Mono<String> remint) {
        return remint
                .switchIfEmpty(Mono.error(unauthorized("no custody token and first-use mint yielded none (fail-closed)")))
                .onErrorMap(
                        err -> !(err instanceof ResponseStatusException) && !(err instanceof ApiException),
                        err -> new ResponseStatusException(HttpStatus.BAD_GATEWAY,
                                "first-use homeserver token mint failed", err));
    }

    /**
     * Reject any {@code upstreamPath} that is not a single-{@code '/'}-leading, same-host
     * RELATIVE path — the SSRF / token+mTLS-cert leak guard. Rejected (400) shapes:
     * <ul>
     *   <li>null / empty / not starting with {@code '/'};</li>
     *   <li>scheme-relative authority: {@code //evil.com/x} (starts with {@code //});</li>
     *   <li>backslash variants browsers/parsers fold to {@code '/'}: a leading
     *       {@code '\'}, a {@code /\} second char, or ANY embedded {@code '\'};</li>
     *   <li>an embedded scheme/authority: {@code https://evil}, {@code x://y} (contains
     *       {@code ://}).</li>
     * </ul>
     * The single-leading-{@code '/'} normal path ({@code /_matrix/client/v3/sync}) passes.
     */
    private static void requireSafePath(String upstreamPath) {
        if (upstreamPath == null || upstreamPath.isEmpty() || upstreamPath.charAt(0) != '/') {
            throw badPath();
        }
        if (upstreamPath.startsWith("//")) {
            throw badPath(); // scheme-relative authority overrides the baseUrl host
        }
        if (upstreamPath.indexOf('\\') >= 0) {
            throw badPath(); // '\' (anywhere) is folded to '/' by many parsers → '\\evil' == '//evil'
        }
        if (upstreamPath.contains("://")) {
            throw badPath(); // embedded absolute URL / scheme
        }
    }

    private static ApiException badPath() {
        return ApiException.badRequest("invalid upstream path (must be a single-'/'-leading same-host relative path)");
    }

    /**
     * If the upstream returned 401, re-mint once and (for a re-issuable bodyless request)
     * retry; any second 401 is fail-closed.
     *
     * <p>BODY METHODS cannot transparently retry: the inbound request body is a once-only
     * stream ({@code ServerHttpRequest.getBody()} over Reactor Netty allows a single
     * subscriber) already consumed by the FIRST upstream write, so a second
     * {@link #exchangeAndRelay} would re-subscribe it and throw ("Only one connection
     * receive subscriber allowed"), surfacing as a 500 — the refresh-on-401 mechanism was
     * silently broken for every POST/PUT/PATCH/DELETE. Instead we re-mint (which REFRESHES
     * the custody row as a side effect) and fail closed 401, so the caller's own retry loads
     * the freshly-minted token and succeeds. This avoids BOTH the 500 AND the infinite-401
     * loop that skipping the re-mint would cause (custody would stay stale). Bodyless
     * requests are freely re-issuable, so they keep the transparent re-mint+retry.
     */
    private Mono<Void> handleRelayResult(Boolean relayed, ServerWebExchange exchange,
                                         String fullPath, Mono<String> remint, boolean bodyMethod) {
        if (Boolean.TRUE.equals(relayed)) {
            // First attempt succeeded — nothing more to do.
            return Mono.empty();
        }
        if (bodyMethod) {
            // Refresh custody for the next request, then fail closed (body not replayable).
            return remint
                    .switchIfEmpty(Mono.error(unauthorized("re-mint failed (fail-closed)")))
                    .then(Mono.error(unauthorized("homeserver token refreshed — retry the request")));
        }
        // Bodyless: re-mint once, retry once transparently, then fail closed.
        return remint
                .switchIfEmpty(Mono.error(unauthorized("re-mint failed (fail-closed)")))
                .flatMap(fresh -> exchangeAndRelay(exchange, fullPath, fresh))
                .flatMap(retryRelayed -> Boolean.TRUE.equals(retryRelayed)
                        ? Mono.empty()
                        : Mono.error(unauthorized("upstream 401 after re-mint (fail-closed)")));
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
        // Relay the upstream response to the caller; signal false on 401 for the re-mint path.
        return headersSpec.exchangeToMono(resp -> relayResponse(resp, exchange));
    }

    /** Relay one upstream response: copy status + headers + body. Returns false on 401 for re-mint. */
    private Mono<Boolean> relayResponse(ClientResponse resp, ServerWebExchange exchange) {
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
