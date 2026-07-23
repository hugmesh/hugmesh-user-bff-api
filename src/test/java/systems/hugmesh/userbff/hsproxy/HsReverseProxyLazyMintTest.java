package systems.hugmesh.userbff.hsproxy;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.HttpHandler;
import org.springframework.http.server.reactive.ReactorHttpHandlerAdapter;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.server.WebHandler;
import org.springframework.web.server.adapter.WebHttpHandlerBuilder;
import reactor.core.publisher.Mono;
import reactor.netty.DisposableServer;
import reactor.netty.http.server.HttpServer;

import java.net.ConnectException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * FIRST-USE lazy mint ({@link HsReverseProxy#forward} on an EMPTY custody load) — the
 * native-login unblock: nothing seeds {@code hs_service_token} at login time, so before
 * this a caller's first hsproxy request failed closed with "no custody token" even though
 * the controller had a working mint wired (fired only on an upstream 401). Same
 * reactor-netty harness as {@link HsReverseProxyStreamingTest} (real HTTP both legs).
 *
 * <p>Pinned behaviours:
 * <ul>
 *   <li>empty custody + working mint → mints ONCE, relays with the minted token;</li>
 *   <li>custody hit → the mint mono is NEVER subscribed (no gratuitous homeserver
 *       traffic on the hot path);</li>
 *   <li>empty custody + empty mint → fail-closed 401 (the old contract);</li>
 *   <li>empty custody + mint transport failure → 502 (homeserver leg down), while a
 *       mint that errors with its OWN status (the broker's unconfigured-password 503)
 *       surfaces verbatim;</li>
 *   <li>minted-then-401 still takes the bounded refresh leg: mint twice, then fail
 *       closed — never an unbounded mint loop.</li>
 * </ul>
 */
class HsReverseProxyLazyMintTest {

    private final AtomicReference<String> lastUpstreamAuth = new AtomicReference<>();
    private final AtomicInteger upstreamCalls = new AtomicInteger();
    private final AtomicInteger mints = new AtomicInteger();
    private final List<DisposableServer> servers = new ArrayList<>();

    @BeforeEach
    void reset() {
        lastUpstreamAuth.set(null);
        upstreamCalls.set(0);
        mints.set(0);
    }

    @AfterEach
    void tearDown() {
        for (DisposableServer s : servers) {
            try {
                s.disposeNow();
            } catch (Exception ignore) {
                // best-effort teardown
            }
        }
        servers.clear();
    }

    private WebClient clientFor(DisposableServer s) {
        return WebClient.builder().baseUrl("http://127.0.0.1:" + s.port()).build();
    }

    /** A mint mono that counts subscriptions and yields the given tokens in order
     *  (repeating the last one) — the shape the controllers wire from the broker. */
    private Mono<String> countingMint(String... tokens) {
        return Mono.defer(() -> {
            int n = mints.getAndIncrement();
            return Mono.just(tokens[Math.min(n, tokens.length - 1)]);
        });
    }

    /** Proxy-under-test over REAL HTTP, same shape as HsReverseProxyStreamingTest. */
    private WebClient proxyClient(HsReverseProxy proxy, Mono<String> load, Mono<String> remint) {
        WebHandler webHandler = exchange -> {
            String path = exchange.getRequest().getPath().value().substring("/proxy".length());
            return proxy.forward(exchange, path, load, remint);
        };
        HttpHandler httpHandler = WebHttpHandlerBuilder.webHandler(webHandler)
                .exceptionHandler(new org.springframework.web.server.handler.ResponseStatusExceptionHandler())
                .build();
        DisposableServer proxyServer = HttpServer.create().host("127.0.0.1").port(0)
                .handle(new ReactorHttpHandlerAdapter(httpHandler))
                .bindNow();
        servers.add(proxyServer);
        return clientFor(proxyServer);
    }

    private DisposableServer echoAuthUpstream() {
        DisposableServer upstream = HttpServer.create().host("127.0.0.1").port(0)
                .route(routes -> routes.get("/_matrix/client/v3/account/whoami", (req, res) -> {
                    upstreamCalls.incrementAndGet();
                    lastUpstreamAuth.set(req.requestHeaders().get(HttpHeaders.AUTHORIZATION));
                    return res.sendString(Mono.just("{\"user_id\":\"@alice:x\"}"));
                }))
                .bindNow();
        servers.add(upstream);
        return upstream;
    }

    @Test
    void firstUse_emptyCustody_mintsOnce_relaysWithMintedToken() {
        DisposableServer upstream = echoAuthUpstream();
        HsReverseProxy proxy = new HsReverseProxy(clientFor(upstream));
        WebClient client = proxyClient(proxy, Mono.empty(), countingMint("MINTED-FIRST-USE"));

        String body = client.get().uri("/proxy/_matrix/client/v3/account/whoami")
                .header(HttpHeaders.AUTHORIZATION, "Bearer CASDOOR-JWT")
                .retrieve().bodyToMono(String.class).block(Duration.ofSeconds(10));

        assertThat(body).contains("@alice:x");
        assertThat(mints.get()).isEqualTo(1);
        // The upstream saw the freshly-minted native token, never the Casdoor bearer.
        assertThat(lastUpstreamAuth.get()).isEqualTo("Bearer MINTED-FIRST-USE");
    }

    @Test
    void custodyHit_neverSubscribesTheMint() {
        DisposableServer upstream = echoAuthUpstream();
        HsReverseProxy proxy = new HsReverseProxy(clientFor(upstream));
        WebClient client = proxyClient(proxy, Mono.just("CUSTODY-TOKEN"), countingMint("NEVER"));

        String body = client.get().uri("/proxy/_matrix/client/v3/account/whoami")
                .retrieve().bodyToMono(String.class).block(Duration.ofSeconds(10));

        assertThat(body).contains("@alice:x");
        assertThat(mints.get()).isZero();
        assertThat(lastUpstreamAuth.get()).isEqualTo("Bearer CUSTODY-TOKEN");
    }

    @Test
    void firstUse_emptyMint_failsClosed401() {
        DisposableServer upstream = echoAuthUpstream();
        HsReverseProxy proxy = new HsReverseProxy(clientFor(upstream));
        WebClient client = proxyClient(proxy, Mono.empty(), Mono.empty());

        Integer status = client.get().uri("/proxy/_matrix/client/v3/account/whoami")
                .exchangeToMono(r -> Mono.just(r.statusCode().value()))
                .block(Duration.ofSeconds(10));

        assertThat(status).isEqualTo(401);
        assertThat(upstreamCalls.get()).isZero(); // never dialed without a token
    }

    @Test
    void firstUse_mintTransportError_mapsTo502() {
        DisposableServer upstream = echoAuthUpstream();
        HsReverseProxy proxy = new HsReverseProxy(clientFor(upstream));
        // The broker leg dying on the wire (sidecar down/unresolvable) is a ConnectException
        // shape, not a status-bearing error.
        WebClient client = proxyClient(proxy, Mono.empty(),
                Mono.error(new ConnectException("tuwunel-proxy:4443 unreachable")));

        Integer status = client.get().uri("/proxy/_matrix/client/v3/account/whoami")
                .exchangeToMono(r -> Mono.just(r.statusCode().value()))
                .block(Duration.ofSeconds(10));

        assertThat(status).isEqualTo(502);
        assertThat(upstreamCalls.get()).isZero();
    }

    @Test
    void firstUse_mintWithOwnStatus_surfacesVerbatim() {
        DisposableServer upstream = echoAuthUpstream();
        HsReverseProxy proxy = new HsReverseProxy(clientFor(upstream));
        // The broker's own fail-closed guard (unconfigured svc-password) is a 503 and must
        // NOT be re-wrapped into a 502.
        WebClient client = proxyClient(proxy, Mono.empty(),
                Mono.error(new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,
                        "homeserver token brokering unavailable: service password not configured")));

        Integer status = client.get().uri("/proxy/_matrix/client/v3/account/whoami")
                .exchangeToMono(r -> Mono.just(r.statusCode().value()))
                .block(Duration.ofSeconds(10));

        assertThat(status).isEqualTo(503);
        assertThat(upstreamCalls.get()).isZero();
    }

    @Test
    void firstUse_mintApiException_surfacesUnwrapped_notRewrappedTo502() {
        // ApiException is NOT a ResponseStatusException subclass (commons hierarchy), so
        // the onErrorMap exclusion must name it explicitly — deleting that clause would
        // re-wrap a status-bearing ApiException into a 502. Pinned at the reactive level
        // (same direct-StepVerifier shape as HsReverseProxyPathGuardTest) because this
        // minimal harness has no ApiExceptionHandler to render it over HTTP.
        HsReverseProxy proxy = new HsReverseProxy(
                org.springframework.web.reactive.function.client.WebClient.builder()
                        .baseUrl("https://tuwunel-proxy.invalid:4443").build());
        org.springframework.web.server.ServerWebExchange exchange =
                org.springframework.mock.web.server.MockServerWebExchange.from(
                        org.springframework.mock.http.server.reactive.MockServerHttpRequest
                                .get("/bff/user/matrix").build());
        systems.hugmesh.commons.web.ApiException fromMint =
                systems.hugmesh.commons.web.ApiException.badRequest("mint refused");

        reactor.test.StepVerifier.create(
                        proxy.forward(exchange, "/_matrix/client/v3/account/whoami",
                                Mono.empty(), Mono.error(fromMint)))
                .expectErrorSatisfies(err -> {
                    assertThat(err).isSameAs(fromMint);
                    assertThat(err).isNotInstanceOf(ResponseStatusException.class);
                })
                .verify();
    }

    @Test
    void firstUseMintedTokenRejectedUpstream_takesBoundedRefreshLeg_thenFailsClosed() {
        // Upstream 401s EVERYTHING: the first-use minted token is rejected, the normal
        // refresh-on-401 leg mints once more and retries, then fails closed — proving the
        // mint is bounded (2 mints, 2 upstream calls), never a mint loop.
        DisposableServer upstream = HttpServer.create().host("127.0.0.1").port(0)
                .route(routes -> routes.get("/_matrix/client/v3/account/whoami", (req, res) -> {
                    upstreamCalls.incrementAndGet();
                    return res.status(HttpStatus.UNAUTHORIZED.value()).send();
                }))
                .bindNow();
        servers.add(upstream);

        HsReverseProxy proxy = new HsReverseProxy(clientFor(upstream));
        WebClient client = proxyClient(proxy, Mono.empty(), countingMint("MINT-1", "MINT-2"));

        Integer status = client.get().uri("/proxy/_matrix/client/v3/account/whoami")
                .exchangeToMono(r -> Mono.just(r.statusCode().value()))
                .block(Duration.ofSeconds(10));

        assertThat(status).isEqualTo(401);
        assertThat(mints.get()).isEqualTo(2);
        assertThat(upstreamCalls.get()).isEqualTo(2);
    }
}
