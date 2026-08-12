package net.hugmesh.userbff.hsproxy;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.HttpHandler;
import org.springframework.http.server.reactive.ReactorHttpHandlerAdapter;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.WebHandler;
import org.springframework.web.server.adapter.WebHttpHandlerBuilder;
import reactor.core.publisher.Mono;
import reactor.netty.DisposableServer;
import reactor.netty.http.server.HttpServer;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Pins the proxy's path/query PASS-THROUGH spelling — the fix for the
 * double-encoding defect that broke every room-scoped Matrix CS-API call.
 *
 * <p>The forwarded path is the caller's RAW request path (already percent-encoded
 * exactly as the client sent it). {@code WebClient}'s DEFAULT uri factory
 * ({@code TEMPLATE_AND_VALUES}) treats {@code .uri(String)} as a URI template and
 * re-escapes {@code '%'}, so {@code /rooms/!r%3Alocalhost/state} reached the
 * homeserver as {@code /rooms/!r%253Alocalhost/state} — tuwunel decoded once and
 * saw a literal {@code %3A} inside the room id (observed live as 400/500
 * {@code M_BAD_JSON}/{@code M_UNKNOWN} on every room-scoped call, while the
 * path-variable-free {@code /sync} and {@code /joined_rooms} kept working). The
 * fix is {@link HsProxyConfig#verbatimUriFactory} ({@code EncodingMode.NONE});
 * these tests drive {@link HsReverseProxy} through a REAL WebFlux pipeline onto a
 * REAL fake homeserver and assert the raw request-target arrives byte-identical
 * in BOTH valid spellings (RFC 3986 permits {@code ':'} literally in a segment;
 * percent-encoding it is equally valid — the proxy must not rewrite either).
 */
class HsReverseProxyPathEncodingTest {

    private final AtomicReference<String> lastUpstreamUri = new AtomicReference<>();
    private final List<DisposableServer> servers = new ArrayList<>();

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

    /** A fake homeserver that records the RAW request-target of every request. */
    private DisposableServer recordingUpstream() {
        DisposableServer s = HttpServer.create().host("127.0.0.1").port(0)
                .handle((req, res) -> {
                    lastUpstreamUri.set(req.uri());
                    return res.sendString(Mono.just("{}"));
                })
                .bindNow();
        servers.add(s);
        return s;
    }

    /** The proxy under test over REAL HTTP, exactly like HsReverseProxyStreamingTest. */
    private WebClient proxyClient(HsReverseProxy proxy) {
        WebHandler webHandler = exchange -> {
            // The RAW path, prefix-stripped — what MatrixProxyController#upstreamPath does.
            String path = exchange.getRequest().getPath().value().substring("/proxy".length());
            return proxy.forward(exchange, path, Mono.just("NATIVE-TOKEN"), Mono.just("REMINTED"));
        };
        HttpHandler httpHandler = WebHttpHandlerBuilder.webHandler(webHandler)
                .exceptionHandler(new org.springframework.web.server.handler.ResponseStatusExceptionHandler())
                .build();
        DisposableServer proxyServer = HttpServer.create().host("127.0.0.1").port(0)
                .handle(new ReactorHttpHandlerAdapter(httpHandler))
                .bindNow();
        servers.add(proxyServer);
        // The caller leg must also send its request-target verbatim (the default
        // template factory would pre-mangle the very spelling under test).
        return WebClient.builder()
                .uriBuilderFactory(HsProxyConfig.verbatimUriFactory("http://127.0.0.1:" + proxyServer.port()))
                .build();
    }

    /** The proxy's upstream leg, built with the SAME factory production wires in. */
    private HsReverseProxy proxyFor(DisposableServer upstream) {
        WebClient upstreamClient = WebClient.builder()
                .uriBuilderFactory(HsProxyConfig.verbatimUriFactory("http://127.0.0.1:" + upstream.port()))
                .build();
        return new HsReverseProxy(upstreamClient);
    }

    private void roundTrip(String requestTarget) {
        WebClient client = proxyClient(proxyFor(recordingUpstream()));
        client.get().uri("/proxy" + requestTarget)
                .header(HttpHeaders.AUTHORIZATION, "Bearer CASDOOR-JWT")
                .retrieve().bodyToMono(String.class).block(Duration.ofSeconds(10));
    }

    @Test
    void encodedRoomIdSegmentArrivesSingleEncoded_neverDoubleEncoded() {
        roundTrip("/_matrix/client/v3/rooms/!r%3Alocalhost/state");
        assertThat(lastUpstreamUri.get())
                .isEqualTo("/_matrix/client/v3/rooms/!r%3Alocalhost/state");
    }

    @Test
    void rawPcharRoomIdSegmentArrivesUnchanged() {
        roundTrip("/_matrix/client/v3/rooms/!r:localhost/state");
        assertThat(lastUpstreamUri.get())
                .isEqualTo("/_matrix/client/v3/rooms/!r:localhost/state");
    }

    @Test
    void queryStringPassesThroughVerbatim() {
        roundTrip("/_matrix/client/v3/rooms/!r:localhost/messages?dir=b&from=t1_2%2B3&limit=50");
        assertThat(lastUpstreamUri.get())
                .isEqualTo("/_matrix/client/v3/rooms/!r:localhost/messages?dir=b&from=t1_2%2B3&limit=50");
    }
}
