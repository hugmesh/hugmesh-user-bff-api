package systems.snapdragon.userbff.silence;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.client.WebClient;

/**
 * Wires the SELF-SILENCE homeserver visibility-hide seams (Matrix/tuwunel +
 * Mastodon/akkoma). Each is ALWAYS present (so the {@code SelfSilenceService} flow is
 * always wired) but defaults to a STUB (null WebClient) unless its
 * {@code external.<platform>.enabled=true} flag is set — at which point a real
 * {@link WebClient} pointed at the in-cluster base URL is injected.
 *
 * <p>Mirrors {@code ExternalBlockConfig}. Base URLs are grounded in the
 * snapdragon-generator manifests (tuwunel :8008, akkoma :4000), env-overridable.
 * SCOPE-GUARD: default OFF + audited + never hard-fail — these are the
 * homeserver.* / external.* gated stub-seams; the real admin verbs are pinned later.
 */
@Configuration
public class HomeserverHideConfig {

    // ── Matrix (tuwunel) directory exclusion ──────────────────────────
    @Bean
    @ConditionalOnProperty(name = "external.matrix.enabled", havingValue = "true")
    public MatrixHideClient liveMatrixHideClient(
            @Value("${external.matrix.base-url:${MATRIX_URL:http://tuwunel.snapdragon-backend.svc.cluster.local:8008}}") String baseUrl) {
        return new MatrixHideClient(WebClient.builder().baseUrl(baseUrl).build());
    }

    @Bean
    @ConditionalOnProperty(name = "external.matrix.enabled", havingValue = "false", matchIfMissing = true)
    public MatrixHideClient stubMatrixHideClient() {
        return new MatrixHideClient(null);
    }

    // ── Mastodon (akkoma) discoverability ─────────────────────────────
    @Bean
    @ConditionalOnProperty(name = "external.mastodon.enabled", havingValue = "true")
    public MastodonHideClient liveMastodonHideClient(
            @Value("${external.mastodon.base-url:${MASTODON_URL:http://akkoma.snapdragon-backend.svc.cluster.local:4000}}") String baseUrl) {
        return new MastodonHideClient(WebClient.builder().baseUrl(baseUrl).build());
    }

    @Bean
    @ConditionalOnProperty(name = "external.mastodon.enabled", havingValue = "false", matchIfMissing = true)
    public MastodonHideClient stubMastodonHideClient() {
        return new MastodonHideClient(null);
    }
}
