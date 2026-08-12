package net.hugmesh.userbff.hsproxy;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.HttpHandler;
import org.springframework.http.server.reactive.ReactorHttpHandlerAdapter;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.WebHandler;
import org.springframework.web.server.adapter.WebHttpHandlerBuilder;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.netty.DisposableServer;
import reactor.netty.http.server.HttpServer;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Functional test of {@link HsReverseProxy} against a REAL fake homeserver (a local
 * reactor-netty {@link HttpServer}) and through a REAL WebFlux pipeline (WebTestClient
 * bound to a thin test controller) — the only way to prove the load-bearing proxy
 * behaviours end-to-end:
 *
 * <ul>
 *   <li><b>bearer strip + native-token inject</b>: the inbound Casdoor bearer is replaced
 *       by the homeserver-native token on the upstream leg;</li>
 *   <li><b>streaming passthrough</b>: a chunked/long-lived upstream body
 *       (the {@code /_matrix/client/v3/sync} shape) is relayed to the caller chunk by
 *       chunk, without buffering the whole stream;</li>
 *   <li><b>refresh-on-401</b>: an upstream 401 triggers exactly ONE re-mint + retry with
 *       the FRESH native token;</li>
 *   <li><b>fail-closed</b>: a second 401 after re-mint surfaces 401 to the caller.</li>
 * </ul>
 */
class HsReverseProxyStreamingTest {

    private DisposableServer upstream;     // the fake homeserver
    private DisposableServer proxyServer;  // the BFF proxy under test, over REAL HTTP
    private final AtomicReference<String> lastUpstreamAuth = new AtomicReference<>();
    private final AtomicInteger calls = new AtomicInteger();
    private final List<DisposableServer> servers = new ArrayList<>();

    @BeforeEach
    void reset() {
        lastUpstreamAuth.set(null);
        calls.set(0);
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

    /**
     * Stand the proxy up behind a REAL reactor-netty HTTP server (so the relayed
     * streaming body is genuine HTTP both legs — the {@code bindToController} mock
     * response drops cross-factory streamed DataBuffers). A {@link WebHandler} drives
     * {@link HsReverseProxy#forward} for the single path under {@code /proxy/**}.
     */
    private WebClient proxyClient(HsReverseProxy proxy, Mono<String> load, Mono<String> remint) {
        WebHandler webHandler = exchange -> {
            String path = exchange.getRequest().getPath().value().substring("/proxy".length());
            return proxy.forward(exchange, path, load, remint);
        };
        HttpHandler httpHandler = WebHttpHandlerBuilder.webHandler(webHandler)
                // Map ResponseStatusException → its status (the fail-closed 401), as a
                // real Spring Boot WebFlux app does via the registered handler.
                .exceptionHandler(new org.springframework.web.server.handler.ResponseStatusExceptionHandler())
                .build();
        proxyServer = HttpServer.create().host("127.0.0.1").port(0)
                .handle(new ReactorHttpHandlerAdapter(httpHandler))
                .bindNow();
        servers.add(proxyServer);
        return clientFor(proxyServer);
    }

    @Test
    void streamingPassthrough_stripsBearer_injectsNativeToken_relaysChunks() {
        upstream = HttpServer.create().host("127.0.0.1").port(0)
                .route(routes -> routes.get("/_matrix/client/v3/sync", (req, res) -> {
                    lastUpstreamAuth.set(req.requestHeaders().get(HttpHeaders.AUTHORIZATION));
                    Flux<String> chunks = Flux.just("{\"a\":1}", "{\"b\":2}", "{\"c\":3}")
                            .delayElements(Duration.ofMillis(20));
                    return res.sendString(chunks);
                }))
                .bindNow();
        servers.add(upstream);

        HsReverseProxy proxy = new HsReverseProxy(clientFor(upstream));
        WebClient client = proxyClient(proxy, Mono.just("NATIVE-MATRIX-TOKEN"), Mono.just("REMINTED"));

        String body = client.get().uri("/proxy/_matrix/client/v3/sync")
                .header(HttpHeaders.AUTHORIZATION, "Bearer CASDOOR-JWT")
                .retrieve().bodyToMono(String.class).block(Duration.ofSeconds(10));

        assertThat(body).isEqualTo("{\"a\":1}{\"b\":2}{\"c\":3}");
        // The upstream saw the NATIVE token, never the Casdoor bearer.
        assertThat(lastUpstreamAuth.get()).isEqualTo("Bearer NATIVE-MATRIX-TOKEN");
    }

    @Test
    void refreshOn401_remintsOnce_retriesWithFreshToken_thenSucceeds() {
        upstream = HttpServer.create().host("127.0.0.1").port(0)
                .route(routes -> routes.get("/_matrix/client/v3/account/whoami", (req, res) -> {
                    calls.incrementAndGet();
                    String auth = req.requestHeaders().get(HttpHeaders.AUTHORIZATION);
                    if ("Bearer STALE".equals(auth)) {
                        return res.status(HttpStatus.UNAUTHORIZED.value()).send();
                    }
                    lastUpstreamAuth.set(auth);
                    return res.sendString(Mono.just("{\"user_id\":\"@alice:x\"}"));
                }))
                .bindNow();
        servers.add(upstream);

        HsReverseProxy proxy = new HsReverseProxy(clientFor(upstream));
        WebClient client = proxyClient(proxy, Mono.just("STALE"), Mono.just("FRESH"));

        String body = client.get().uri("/proxy/_matrix/client/v3/account/whoami")
                .header(HttpHeaders.AUTHORIZATION, "Bearer CASDOOR-JWT")
                .retrieve().bodyToMono(String.class).block(Duration.ofSeconds(10));

        assertThat(body).contains("@alice:x");
        assertThat(calls.get()).isEqualTo(2); // stale 401 + fresh retry
        assertThat(lastUpstreamAuth.get()).isEqualTo("Bearer FRESH");
    }

    @Test
    void forwardingMetadataStripped_clientDefaultProtoWins() {
        // Inbound X-Forwarded-* / Forwarded never reach the upstream (proxy hygiene:
        // the BFF is the client on that leg), so the WebClient's own default
        // X-Forwarded-Proto (asserted on plain-HTTP homeserver legs — mainline
        // Mastodon's force_ssl 308s anything else) is authoritative. A relayed
        // inbound "http" would override it via HttpHeaders.put and re-break the leg.
        AtomicReference<String> xfp = new AtomicReference<>();
        AtomicReference<String> xff = new AtomicReference<>();
        upstream = HttpServer.create().host("127.0.0.1").port(0)
                .route(routes -> routes.get("/api/v1/accounts/verify_credentials", (req, res) -> {
                    xfp.set(req.requestHeaders().get("X-Forwarded-Proto"));
                    xff.set(req.requestHeaders().get("X-Forwarded-For"));
                    return res.sendString(Mono.just("{\"ok\":true}"));
                }))
                .bindNow();
        servers.add(upstream);

        WebClient upstreamClient = WebClient.builder()
                .baseUrl("http://127.0.0.1:" + upstream.port())
                .defaultHeader("X-Forwarded-Proto", "https")   // the HsProxyConfig plain-HTTP posture
                .build();
        HsReverseProxy proxy = new HsReverseProxy(upstreamClient);
        WebClient client = proxyClient(proxy, Mono.just("NATIVE-TOKEN"), Mono.just("REMINTED"));

        String body = client.get().uri("/proxy/api/v1/accounts/verify_credentials")
                .header("X-Forwarded-Proto", "http")           // the caller's edge metadata
                .header("X-Forwarded-For", "203.0.113.7")
                .retrieve().bodyToMono(String.class).block(Duration.ofSeconds(10));

        assertThat(body).contains("ok");
        assertThat(xfp.get()).isEqualTo("https"); // default survived; inbound stripped
        assertThat(xff.get()).isNull();
    }

    @Test
    void refreshOn401_secondFailureFailsClosedWith401() {
        upstream = HttpServer.create().host("127.0.0.1").port(0)
                .route(routes -> routes.get("/_matrix/client/v3/account/whoami", (req, res) -> {
                    calls.incrementAndGet();
                    return res.status(HttpStatus.UNAUTHORIZED.value()).send();
                }))
                .bindNow();
        servers.add(upstream);

        HsReverseProxy proxy = new HsReverseProxy(clientFor(upstream));
        WebClient client = proxyClient(proxy, Mono.just("STALE"), Mono.just("FRESH"));

        Integer status = client.get().uri("/proxy/_matrix/client/v3/account/whoami")
                .header(HttpHeaders.AUTHORIZATION, "Bearer CASDOOR-JWT")
                .exchangeToMono(r -> Mono.just(r.statusCode().value()))
                .block(Duration.ofSeconds(10));

        assertThat(status).isEqualTo(401); // fail-closed to the caller
        assertThat(calls.get()).isEqualTo(2); // one initial + one retry, then fail closed
    }

    @Test
    void bodyMethod_401_refreshesCustodyThenFailsClosed401_neverReSubscribesBody() {
        // A PUT/POST whose token 401s must NOT re-subscribe the once-only request body on a
        // retry (that threw "Only one connection receive subscriber allowed" -> 500). Instead:
        // exactly ONE upstream write (no retry write), the custody row re-minted once (so the
        // caller's own retry loads a fresh token), and a clean 401 back to the caller.
        AtomicInteger mints = new AtomicInteger();
        upstream = HttpServer.create().host("127.0.0.1").port(0)
                .route(routes -> routes.put("/_matrix/client/v3/rooms/r/send/m.room.message/t",
                        (req, res) -> {
                            calls.incrementAndGet();
                            // Drain the body so a real single-subscription write completes.
                            return req.receive().aggregate().then(
                                    res.status(HttpStatus.UNAUTHORIZED.value()).send());
                        }))
                .bindNow();
        servers.add(upstream);

        HsReverseProxy proxy = new HsReverseProxy(clientFor(upstream));
        Mono<String> remint = Mono.fromSupplier(() -> { mints.incrementAndGet(); return "FRESH"; });
        WebClient client = proxyClient(proxy, Mono.just("STALE"), remint);

        Integer status = client.put().uri("/proxy/_matrix/client/v3/rooms/r/send/m.room.message/t")
                .header(HttpHeaders.AUTHORIZATION, "Bearer CASDOOR-JWT")
                .bodyValue("{\"msgtype\":\"m.text\",\"body\":\"hi\"}")
                .exchangeToMono(r -> Mono.just(r.statusCode().value()))
                .block(Duration.ofSeconds(10));

        assertThat(status).isEqualTo(401);   // clean fail-closed, NOT a 500 from a re-subscribe
        assertThat(calls.get()).isEqualTo(1); // exactly ONE upstream write (no body-replay retry)
        assertThat(mints.get()).isEqualTo(1); // custody refreshed once for the caller's retry
    }
}
