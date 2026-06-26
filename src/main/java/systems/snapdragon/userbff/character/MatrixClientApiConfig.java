package systems.snapdragon.userbff.character;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.client.WebClient;

/**
 * Wires the {@link MatrixClientApiClient} used by {@link StickerPackRegistrationService}
 * to register the owner's ACTIVE stickers as an MSC2545 {@code im.ponies.user_emotes}
 * pack. The client is ALWAYS present (so the registration flow is always wired) but
 * defaults to STUB (null WebClient) unless {@code sticker.matrix.register.enabled=true}
 * is set — at which point a real {@link WebClient} pointed at the in-cluster Matrix
 * (tuwunel) base URL is injected. Base URL grounded in the snapdragon-generator manifests
 * (tuwunel :8008), env-overridable via {@code MATRIX_URL}.
 *
 * <p>This MIRRORS {@code MatrixMediaConfig} / {@code ExternalBlockConfig}: a live bean
 * gated on the enabled flag + a stub bean (null WebClient) as the {@code matchIfMissing}
 * default, so the sticker-pack REGISTRATION half ships DARK until the per-user homeserver
 * token brokering is validated against a real homeserver.
 */
@Configuration
public class MatrixClientApiConfig {

    @Bean
    @ConditionalOnProperty(name = "sticker.matrix.register.enabled", havingValue = "true")
    public MatrixClientApiClient liveMatrixClientApiClient(
            @Value("${sticker.matrix.base-url:${MATRIX_URL:http://tuwunel.snapdragon-backend.svc.cluster.local:8008}}") String baseUrl) {
        return new MatrixClientApiClient(WebClient.builder().baseUrl(baseUrl).build());
    }

    @Bean
    @ConditionalOnProperty(name = "sticker.matrix.register.enabled", havingValue = "false", matchIfMissing = true)
    public MatrixClientApiClient stubMatrixClientApiClient() {
        return new MatrixClientApiClient(null);
    }
}
