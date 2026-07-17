package systems.snapdragon.userbff.media;

import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;
import org.junit.jupiter.api.Test;
import org.springframework.http.client.reactive.ClientHttpConnector;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.netty.http.client.HttpClient;
import systems.snapdragon.userbff.federation.FederationHttpClientSsl;

import java.lang.reflect.Field;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Pins the OUTBOUND mTLS posture of the poison-worker leg.
 *
 * <p>The {@code snapdragon-media-poisoner} worker terminates mTLS ITSELF and serves with
 * {@code ssl.CERT_REQUIRED} (generator: media-poisoner deployment mounts the ESO
 * {@code media-poisoner-mtls} Secret; probes are tcpSocket precisely because a certless
 * handshake is rejected). A certless caller therefore cannot talk to it at all, so the
 * {@link PoisonWorkerClient}'s WebClient MUST carry the {@link FederationHttpClientSsl}
 * client-presentation connector — exactly like the homeserver-proxy leg in the same
 * config.
 *
 * <p>The assertion is deep rather than a mere "the customizer was invoked": it reaches the
 * connector actually installed on the built WebClient and asserts the reactor-netty client
 * behind it is TLS-secured. Removing the {@code .clientConnector(...)} line flips
 * {@code isSecure()} to false and fails {@link #poisonWorkerClient_carriesMtlsConnector()}.
 * Cert LOADING itself is covered by {@code FederationHttpClientSslTest}; here the
 * customizer is stubbed so the test stays offline and store-free.
 */
class MediaWebClientConfigTest {

    private static SslContext clientSsl() throws Exception {
        return SslContextBuilder.forClient()
                .trustManager(InsecureTrustManagerFactory.INSTANCE).build();
    }

    private static MediaPoisoningProperties props() {
        MediaPoisoningProperties p = new MediaPoisoningProperties();
        p.setMaxUploadBytes(1024);
        p.setHealthTimeoutMs(2000);
        p.setTimeoutMs(120000);
        return p;
    }

    private static Object field(Object target, String name) throws Exception {
        Field f = target.getClass().getDeclaredField(name);
        f.setAccessible(true);
        return f.get(target);
    }

    /** The WebClient the PoisonWorkerClient will actually call the worker with. */
    private static WebClient webClientOf(PoisonWorkerClient client) throws Exception {
        return (WebClient) field(client, "http");
    }

    /** True when the connector installed on this WebClient is TLS-secured. */
    private static boolean connectorIsSecure(WebClient web) throws Exception {
        Object exchangeFunction = field(web, "exchangeFunction");
        ClientHttpConnector connector = (ClientHttpConnector) field(exchangeFunction, "connector");
        assertThat(connector).isInstanceOf(ReactorClientHttpConnector.class);
        HttpClient httpClient = (HttpClient) field(connector, "httpClient");
        return httpClient.configuration().isSecure();
    }

    /** A FederationHttpClientSsl that applies REAL TLS, and counts its invocations. */
    private static FederationHttpClientSsl applyingMtls(AtomicInteger calls, SslContext ssl) {
        return new FederationHttpClientSsl() {
            @Override
            public HttpClient customize(HttpClient httpClient) {
                calls.incrementAndGet();
                return httpClient.secure(spec -> spec.sslContext(ssl));
            }
        };
    }

    // ── the drift this test exists to prevent ────────────────────────────────

    @Test
    void poisonWorkerClient_carriesMtlsConnector() throws Exception {
        AtomicInteger calls = new AtomicInteger();
        PoisonWorkerClient client = new MediaWebClientConfig().poisonWorkerClient(
                props(), applyingMtls(calls, clientSsl()),
                "https://snapdragon-media-poisoner.snapdragon-backend.svc.cluster.local:8080");

        WebClient web = webClientOf(client);
        assertThat(web).isNotNull();
        // The mTLS customizer was applied to the client that backs the WebClient...
        assertThat(calls.get()).isEqualTo(1);
        // ...and the resulting secured connector is the one actually installed.
        assertThat(connectorIsSecure(web)).isTrue();
    }

    // ── the absent-worker seam is unchanged (no WebClient, no SSL work) ──────

    @Test
    void blankWorkerUrl_wiresNullWebClientAndNeverBuildsSsl() throws Exception {
        AtomicInteger calls = new AtomicInteger();
        PoisonWorkerClient client = new MediaWebClientConfig().poisonWorkerClient(
                props(), applyingMtls(calls, clientSsl()), "");

        // Lean fallback seam: null WebClient => capability reports backend=none.
        assertThat(webClientOf(client)).isNull();
        // No worker wired => no reason to touch the keystore at all.
        assertThat(calls.get()).isZero();
    }

    // ── blast radius: the gate (default OFF) keeps local/dev/CI on plain HTTP ─

    @Test
    void mtlsGateDisabled_leavesConnectorUnsecured() throws Exception {
        // A REAL FederationHttpClientSsl: enabled=false by default => customize() is a
        // no-op, so dev/CI (no stores mounted) still gets a plain connector and boots.
        FederationHttpClientSsl realDisabled = new FederationHttpClientSsl();
        assertThat(realDisabled.isEnabled()).isFalse();

        PoisonWorkerClient client = new MediaWebClientConfig().poisonWorkerClient(
                props(), realDisabled, "http://localhost:8080");

        WebClient web = webClientOf(client);
        assertThat(web).isNotNull();
        assertThat(connectorIsSecure(web)).isFalse();
    }
}
