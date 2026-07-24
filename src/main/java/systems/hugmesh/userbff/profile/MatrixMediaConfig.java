package systems.hugmesh.userbff.profile;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.client.WebClient;

/**
 * Wires the {@link MatrixMediaClient} that uploads profile-picture bytes to the
 * in-cluster Matrix (tuwunel) media repository. The client is ALWAYS present (so the
 * {@link AvatarService} flow is always wired) but defaults to STUB (null WebClient)
 * unless {@code avatar.matrix.enabled=true} is set — at which point a real
 * {@link WebClient} pointed at the in-cluster base URL is injected. Base URL is
 * grounded in the hugmesh-generator manifests (tuwunel :8008), env-overridable.
 *
 * <p>This MIRRORS {@code ExternalBlockConfig}: a live bean gated on the enabled flag
 * + a stub bean (null WebClient) that is the {@code matchIfMissing} default, so the
 * avatar feature ships dark until the homeserver media-token brokering is validated.
 */
@Configuration
public class MatrixMediaConfig {

    @Bean
    @ConditionalOnProperty(name = "avatar.matrix.enabled", havingValue = "true")
    public MatrixMediaClient liveMatrixMediaClient(
            @Value("${avatar.matrix.base-url:${MATRIX_URL:http://tuwunel.snapdragon-backend.svc.cluster.local:8008}}") String baseUrl) {
        return new MatrixMediaClient(WebClient.builder().baseUrl(baseUrl).build());
    }

    @Bean
    @ConditionalOnProperty(name = "avatar.matrix.enabled", havingValue = "false", matchIfMissing = true)
    public MatrixMediaClient stubMatrixMediaClient() {
        return new MatrixMediaClient(null);
    }
}
