package systems.hugmesh.userbff.block;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.client.WebClient;

/**
 * Wires the external Matrix (tuwunel) + Mastodon (Akkoma) self-block clients. Each
 * is ALWAYS present (so the {@code BlockService} flow is always wired) but defaults
 * to STUB (null WebClient) unless its {@code block.{platform}.enabled=true} flag is
 * set — at which point a real {@link WebClient} pointed at the in-cluster base URL
 * is injected. Base URLs are grounded in the hugmesh-generator manifests
 * (tuwunel :8008, akkoma :4000), env-overridable.
 */
@Configuration
public class ExternalBlockConfig {

    // ── Matrix (tuwunel) ──────────────────────────────────────────────
    @Bean
    @ConditionalOnProperty(name = "block.matrix.enabled", havingValue = "true")
    public MatrixBlockClient liveMatrixBlockClient(
            @Value("${block.matrix.base-url:${MATRIX_URL:http://tuwunel.hugmesh-backend.svc.cluster.local:8008}}") String baseUrl) {
        return new MatrixBlockClient(WebClient.builder().baseUrl(baseUrl).build());
    }

    @Bean
    @ConditionalOnProperty(name = "block.matrix.enabled", havingValue = "false", matchIfMissing = true)
    public MatrixBlockClient stubMatrixBlockClient() {
        return new MatrixBlockClient(null);
    }

    // ── Mastodon (Akkoma) ─────────────────────────────────────────────
    @Bean
    @ConditionalOnProperty(name = "block.mastodon.enabled", havingValue = "true")
    public MastodonBlockClient liveMastodonBlockClient(
            @Value("${block.mastodon.base-url:${MASTODON_URL:http://akkoma.hugmesh-backend.svc.cluster.local:4000}}") String baseUrl) {
        return new MastodonBlockClient(WebClient.builder().baseUrl(baseUrl).build());
    }

    @Bean
    @ConditionalOnProperty(name = "block.mastodon.enabled", havingValue = "false", matchIfMissing = true)
    public MastodonBlockClient stubMastodonBlockClient() {
        return new MastodonBlockClient(null);
    }
}
