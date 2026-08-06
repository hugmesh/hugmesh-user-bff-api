package systems.hugmesh.userbff.profile;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.Base64;
import java.util.Map;

/**
 * Client for the shared on-prem edge-AI content-analysis service (the {@code edge-ai-analysis}
 * FastAPI wrapper added in the generator; reached in-cluster at
 * {@code hugmesh-edge-ai-analysis.hugmesh-inference:8080}). Used to vision-moderate a
 * profile picture BEFORE it is published to the homeserver media repo.
 *
 * <p>Wired by {@link ImageModerationConfig} as a live bean (real {@link WebClient}) ONLY when
 * {@code moderation.image.enabled=true}; otherwise a STUB bean (null {@link WebClient}) is the
 * default, so the avatar feature is UNCHANGED on a mesh without an edge-AI node (capability-gating).
 *
 * <p><b>Fail posture:</b>
 * <ul>
 *   <li>DISABLED (null client) ⇒ {@link ModerationVerdict#allow()} — the moderation feature is
 *       simply off; uploads behave exactly as before.</li>
 *   <li>ENABLED but the service errors / times out ⇒ {@link ModerationVerdict#reject(String)}
 *       — FAIL-CLOSED: an unscanned image must not go live when scanning was meant to happen.</li>
 * </ul>
 *
 * <p>Boot-4 codec note: the response is read as {@code String} and parsed with a Jackson-2
 * {@link ObjectMapper} off the WebFlux codec path (the reactive codec is Jackson-3), matching
 * the established broker/inference pattern. Image bytes are never logged.
 */
public class EdgeAiAnalysisClient {

    private static final Logger log = LoggerFactory.getLogger(EdgeAiAnalysisClient.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    /** Null unless moderation.image.enabled=true — when null every call is a documented allow. */
    private final WebClient http;
    private final Duration timeout;

    public EdgeAiAnalysisClient(WebClient http, long timeoutMs) {
        this.http = http;
        this.timeout = Duration.ofMillis(timeoutMs > 0 ? timeoutMs : 15_000);
    }

    /** True iff a real edge-AI analysis node is wired (the capability-gating flag). */
    public boolean isEnabled() {
        return http != null;
    }

    /**
     * Moderate an image. Returns {@code allow} when disabled; the service's
     * {@code allow|flag|reject} verdict when enabled; {@code reject} (fail-closed) on any error.
     */
    public Mono<ModerationVerdict> moderate(byte[] bytes) {
        if (http == null) {
            return Mono.just(ModerationVerdict.allow());
        }
        String b64 = Base64.getEncoder().encodeToString(bytes);
        return http.post().uri("/v1/analyze/content/moderate")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(Map.of("image_b64", b64))
                .retrieve()
                .bodyToMono(String.class)
                .timeout(timeout)
                .map(EdgeAiAnalysisClient::parseVerdict)
                .onErrorResume(e -> {
                    // FAIL-CLOSED: the scanner was meant to run but couldn't — do not publish.
                    log.warn("[avatar-moderation] edge-ai-analysis unavailable, FAIL-CLOSED (reject): {}",
                            e.toString());
                    return Mono.just(ModerationVerdict.reject("edge-ai-analysis-unavailable"));
                });
    }

    /** Map the {@code /v1/analyze/content/moderate} JSON body to a {@link ModerationVerdict}. */
    static ModerationVerdict parseVerdict(String json) {
        try {
            JsonNode r = MAPPER.readTree(json).path("result");
            String action = r.path("action").asText("reject");          // missing => fail-closed
            String classification = r.path("classification").asText("unknown");
            double confidence = r.path("confidence").asDouble(0.0);
            boolean policyHit = r.path("policy_hit").asBoolean(true);    // missing => fail-closed
            String phash = r.hasNonNull("perceptual_hash") ? r.path("perceptual_hash").asText() : null;
            return new ModerationVerdict(action, classification, confidence, policyHit, phash);
        } catch (Exception e) {
            log.warn("[avatar-moderation] unparseable analysis response, FAIL-CLOSED (reject)");
            return ModerationVerdict.reject("analysis-unparseable");
        }
    }
}
