package systems.snapdragon.userbff.profile;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.client.WebClient;

/**
 * Wires the {@link EdgeAiAnalysisClient} that vision-moderates a profile picture before it is
 * published. The client is ALWAYS present (so the {@link AvatarService} flow is always wired)
 * but defaults to STUB (null WebClient ⇒ allow-all) unless {@code moderation.image.enabled=true}
 * — at which point a real {@link WebClient} pointed at the in-cluster edge-ai-analysis service is
 * injected. MIRRORS {@code MatrixMediaConfig}: a live bean gated on the enabled flag + a stub bean
 * ({@code matchIfMissing} default), so avatar moderation ships DARK until an edge-AI node exists.
 */
@Configuration
public class ImageModerationConfig {

    @Bean
    @ConditionalOnProperty(name = "moderation.image.enabled", havingValue = "true")
    public EdgeAiAnalysisClient liveImageModerationClient(
            @Value("${moderation.image.base-url:http://snapdragon-edge-ai-analysis.snapdragon-inference.svc.cluster.local:8080}") String baseUrl,
            @Value("${moderation.image.timeout-ms:15000}") long timeoutMs) {
        return new EdgeAiAnalysisClient(WebClient.builder().baseUrl(baseUrl).build(), timeoutMs);
    }

    @Bean
    @ConditionalOnProperty(name = "moderation.image.enabled", havingValue = "false", matchIfMissing = true)
    public EdgeAiAnalysisClient stubImageModerationClient() {
        return new EdgeAiAnalysisClient(null, 0);
    }
}
