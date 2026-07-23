package systems.hugmesh.userbff.client;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.netty.http.client.HttpClient;
import systems.hugmesh.userbff.federation.FederationHttpClientSsl;

/**
 * Wires the CONNECTED APPS & DEVICES homeserver seams (Matrix + Mastodon) used by
 * {@link ConnectedClientsService} to list/revoke the user's native clients through the
 * mTLS proxy. Each seam is ALWAYS present (so the service flow is always wired) but
 * defaults to a STUB (null WebClient) unless its {@code external.<platform>.enabled=true}
 * flag is set — at which point a real {@link WebClient} pointed at the in-cluster base
 * URL, carrying this BFF's PKI client identity (the same {@link FederationHttpClientSsl}
 * outbound mTLS the federation client uses), is injected.
 *
 * <p>Mirrors {@code HomeserverHideConfig}; reuses the {@code external.matrix.*} /
 * {@code external.mastodon.*} flags + base URLs (grounded in the hugmesh-generator
 * manifests: tuwunel :8008, akkoma :4000), env-overridable. SCOPE-GUARD: default OFF
 * + never hard-fail — these are gated stub-seams; the live homeserver client-API
 * read/revoke shapes are pinned later.
 */
@Configuration
public class ConnectedClientsConfig {

    /** Decorate a reactor-netty client with the outbound mTLS identity when enabled. */
    private static WebClient secured(FederationHttpClientSsl mtls, String baseUrl) {
        HttpClient httpClient = mtls.customize(HttpClient.create());
        return WebClient.builder()
                .baseUrl(baseUrl)
                .clientConnector(new ReactorClientHttpConnector(httpClient))
                .build();
    }

    // ── Matrix (tuwunel) connected devices ────────────────────────────
    @Bean
    @ConditionalOnProperty(name = "external.matrix.enabled", havingValue = "true")
    public MatrixClientsClient liveMatrixClientsClient(
            FederationHttpClientSsl mtls,
            @Value("${external.matrix.base-url:${MATRIX_URL:http://tuwunel.snapdragon-backend.svc.cluster.local:8008}}") String baseUrl) {
        return new MatrixClientsClient(secured(mtls, baseUrl));
    }

    @Bean
    @ConditionalOnProperty(name = "external.matrix.enabled", havingValue = "false", matchIfMissing = true)
    public MatrixClientsClient stubMatrixClientsClient() {
        return new MatrixClientsClient(null);
    }

    // ── Mastodon (akkoma) connected apps ──────────────────────────────
    @Bean
    @ConditionalOnProperty(name = "external.mastodon.enabled", havingValue = "true")
    public MastodonClientsClient liveMastodonClientsClient(
            FederationHttpClientSsl mtls,
            @Value("${external.mastodon.base-url:${MASTODON_URL:http://akkoma.snapdragon-backend.svc.cluster.local:4000}}") String baseUrl) {
        return new MastodonClientsClient(secured(mtls, baseUrl));
    }

    @Bean
    @ConditionalOnProperty(name = "external.mastodon.enabled", havingValue = "false", matchIfMissing = true)
    public MastodonClientsClient stubMastodonClientsClient() {
        return new MastodonClientsClient(null);
    }
}
