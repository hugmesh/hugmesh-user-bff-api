package systems.snapdragon.userbff.media;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.netty.http.client.HttpClient;
import systems.snapdragon.userbff.federation.FederationHttpClientSsl;
import systems.snapdragon.userbff.hsproxy.HsTokenCustody;
import systems.snapdragon.userbff.hsproxy.ServiceTokenBroker;

import java.time.Duration;

/**
 * Wires the media-proxy collaborators:
 * <ul>
 *   <li>the {@link PoisonWorkerClient} to the OPTIONAL {@code snapdragon-media-poisoner}
 *       worker (plain in-cluster HTTP — the worker is a backend service, not behind the
 *       mTLS homeserver proxies). When {@code app.media.poisoning.worker-url} is blank the
 *       client is wired with a {@code null} WebClient and reports the heavy tier absent
 *       (lean fallback);</li>
 *   <li>the {@link HomeserverMediaClient} to the EXISTING mTLS homeserver proxies
 *       ({@code akkoma-proxy:4443} / {@code tuwunel-proxy:4443}, {@code ssl_verify_client
 *       on}). It REUSES {@link FederationHttpClientSsl} (this BFF's cluster-CA client
 *       identity + truststore) for the client-presentation handshake. Authorization on the
 *       outbound leg is the caller's per-user homeserver-NATIVE token (loaded/minted via
 *       {@link HsTokenCustody}/{@link ServiceTokenBroker} inside the client), NOT the
 *       caller's Casdoor/custody JWT — the homeserver is a distinct trust domain, so the
 *       platform identity must never be forwarded there (matching the reverse-proxy).</li>
 * </ul>
 *
 * <p>The two homeserver WebClients are gated per platform ({@code app.media.proxy.
 * mastodon.enabled} / {@code .matrix.enabled}, default OFF) so local/dev/CI (no proxy,
 * no stores) wires {@code null} clients and the feature degrades to forward-through —
 * mirroring the {@code ExternalBlockConfig} / {@code HomeserverHideConfig} stub-seam
 * convention.
 */
@Configuration
@EnableConfigurationProperties(MediaPoisoningProperties.class)
public class MediaWebClientConfig {

    /**
     * The poison worker client. {@code worker-url} blank ⇒ {@code null} WebClient ⇒ the
     * client reports {@code backend=none} so the service engages the lean fallback. The
     * per-job timeout is the configured hard latency budget; the health probe gets the
     * (short) health timeout.
     */
    @Bean
    public PoisonWorkerClient poisonWorkerClient(
            MediaPoisoningProperties props,
            @Value("${app.media.poisoning.worker-url:}") String workerUrl) {
        WebClient web = (workerUrl == null || workerUrl.isBlank())
                ? null
                : WebClient.builder()
                    .baseUrl(workerUrl)
                    .codecs(c -> c.defaultCodecs().maxInMemorySize((int) props.getMaxUploadBytes() + 4096))
                    .build();
        return new PoisonWorkerClient(web,
                Duration.ofMillis(props.getHealthTimeoutMs()),
                Duration.ofMillis(props.getTimeoutMs()));
    }

    /**
     * The homeserver upload/refetch client over the mTLS proxies. Each platform's
     * WebClient is built only when {@code app.media.proxy.<platform>.enabled=true};
     * otherwise it is {@code null} (forward-through unavailable ⇒ a clean 502 rather than
     * a NPE). The mTLS client-presentation + bearer-forward are reused from federation.
     */
    @Bean
    public HomeserverMediaClient homeserverMediaClient(
            MediaPoisoningProperties props,
            FederationHttpClientSsl mtls,
            HsTokenCustody custody,
            ServiceTokenBroker broker,
            @Value("${app.media.proxy.mastodon.enabled:false}") boolean mastodonEnabled,
            @Value("${app.media.proxy.mastodon.base-url:https://akkoma-proxy.snapdragon-backend.svc.cluster.local:4443}") String mastodonUrl,
            @Value("${app.media.proxy.matrix.enabled:false}") boolean matrixEnabled,
            @Value("${app.media.proxy.matrix.base-url:https://tuwunel-proxy.snapdragon-backend.svc.cluster.local:4443}") String matrixUrl) {
        WebClient mastodon = mastodonEnabled ? proxyClient(mastodonUrl, mtls, props) : null;
        WebClient matrix = matrixEnabled ? proxyClient(matrixUrl, mtls, props) : null;
        return new HomeserverMediaClient(mastodon, matrix, custody, broker);
    }

    /** A WebClient to one homeserver proxy: mTLS client-presentation + a buffer sized for
     *  the (poisoned) image bytes. NO Casdoor-bearer forward filter — the homeserver is a
     *  distinct trust domain; {@link HomeserverMediaClient} injects the per-user
     *  homeserver-NATIVE token on each call instead (see its class doc). */
    private static WebClient proxyClient(String baseUrl, FederationHttpClientSsl mtls,
                                         MediaPoisoningProperties props) {
        HttpClient httpClient = mtls.customize(HttpClient.create());
        return WebClient.builder()
                .baseUrl(baseUrl)
                .clientConnector(new ReactorClientHttpConnector(httpClient))
                .codecs(c -> c.defaultCodecs().maxInMemorySize((int) props.getMaxUploadBytes() + 4096))
                .build();
    }
}
