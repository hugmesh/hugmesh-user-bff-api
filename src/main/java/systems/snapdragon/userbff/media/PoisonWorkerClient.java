package systems.snapdragon.userbff.media;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import systems.snapdragon.userbff.media.PoisonModels.Backend;
import systems.snapdragon.userbff.media.PoisonModels.Health;
import systems.snapdragon.userbff.media.PoisonModels.PoisonResult;
import systems.snapdragon.userbff.media.PoisonModels.SurvivalVerdict;

import java.time.Duration;
import java.util.List;

/**
 * Reactive WebClient CLIENT of the OPTIONAL {@code snapdragon-media-poisoner} worker
 * (in-cluster DNS, default {@code http://snapdragon-media-poisoner.snapdragon-backend
 * .svc.cluster.local:8080}). The worker runs on the x86/GPU heavy tier; on a Pi5-only
 * cluster its pod stays {@code Pending} and this client's {@link #capability()} reports
 * {@code backend=none} (heavy tier absent) so the {@link MediaPoisonService} engages the
 * lean fallback — there is NO Eureka/Config/Task, just a k8s protocol probe of the
 * Service's {@code /health}.
 *
 * <p>Three calls, each with a hard timeout so a slow/saturated worker never blocks the
 * BFF request indefinitely:
 * <ul>
 *   <li>{@link #capability()} — GET {@code /health} → backend + offered modes + ETA;
 *       a non-2xx / timeout / connect error degrades to {@code backend=none};</li>
 *   <li>{@link #poison} — POST {@code /poison} the original bytes + mode + the served
 *       thumbnail sizes to ALSO cloak; the worker returns the poisoned original + each
 *       sized derivative (so no clean derivative exists);</li>
 *   <li>{@link #checkSurvival} — POST {@code /survival} a re-fetched served artifact
 *       (post homeserver ingest) → whether the perturbation SURVIVED (the round-trip
 *       gate's per-artifact verdict).</li>
 * </ul>
 *
 * <p>When the worker is wired with a {@code null} {@link WebClient} (the configured
 * fallback / no worker URL) every method degrades to "absent": {@link #capability()}
 * returns {@code backend=none} and {@link #poison}/{@link #checkSurvival} return empty,
 * so the service forwards-through with {@code status=skipped}. This mirrors the
 * stub-seam pattern of {@code MatrixBlockClient}/{@code MastodonHideClient}.
 */
public class PoisonWorkerClient {

    private static final Logger log = LoggerFactory.getLogger(PoisonWorkerClient.class);

    /** Null when no worker is wired — every probe then reports the heavy tier absent. */
    private final WebClient http;
    private final Duration healthTimeout;
    private final Duration jobTimeout;

    public PoisonWorkerClient(WebClient http, Duration healthTimeout, Duration jobTimeout) {
        this.http = http;
        this.healthTimeout = healthTimeout;
        this.jobTimeout = jobTimeout;
    }

    /**
     * Probe the worker {@code /health}. ANY failure (no worker wired, connect refused,
     * non-2xx, timeout) resolves to {@code backend=none} — i.e. "heavy tier absent" —
     * NEVER an error, so capability queries are safe to call on every composer-open and
     * the fallback path is the natural default.
     */
    public Mono<Health> capability() {
        if (http == null) return Mono.just(absent());
        return http.get()
                .uri("/health")
                .retrieve()
                .bodyToMono(Health.class)
                .timeout(healthTimeout)
                .onErrorResume(e -> {
                    log.debug("[poison-worker] /health unavailable -> heavy tier absent: {}", e.toString());
                    return Mono.just(absent());
                })
                .map(h -> h == null ? absent() : h);
    }

    /** The "absent" health: backend none, no modes — the lean-fallback trigger. */
    static Health absent() {
        return new Health(Backend.NONE.wire(), List.of(), null);
    }

    /**
     * Submit a poison job. The original bytes are sent as octet-stream with the mode +
     * the served thumbnail sizes pinned as headers (so the worker poisons the original
     * AND every size). On ANY failure the result is empty so the service records
     * {@code failed} and falls back rather than blocking the post. Bounded by
     * {@link #jobTimeout} (the hard per-job latency budget).
     */
    public Mono<PoisonResult> poison(byte[] original, String mode, String filename,
                                     String contentType, List<String> thumbnailSizes) {
        if (http == null) return Mono.empty();
        return http.post()
                .uri("/poison")
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .header("X-Cloak-Mode", mode)
                .header("X-Cloak-Filename", filename == null ? "" : filename)
                .header("X-Cloak-Content-Type", contentType == null ? "application/octet-stream" : contentType)
                .header("X-Cloak-Thumbnail-Sizes", String.join(",", thumbnailSizes))
                .bodyValue(original)
                .retrieve()
                .bodyToMono(PoisonResult.class)
                .timeout(jobTimeout)
                .onErrorResume(e -> {
                    log.warn("[poison-worker] poison job failed (mode={}): {}", mode, e.toString());
                    return Mono.empty();
                });
    }

    /**
     * Run the perturbation-presence check on ONE re-fetched served artifact (the
     * round-trip survival gate). {@code servedBytes} are what the homeserver actually
     * serves AFTER its re-encode/downscale; the worker answers whether the cloak signal
     * survived. ANY failure resolves to {@code present=false} (fail-honest: a check we
     * could not run is NOT a survival), so the badge degrades rather than over-claims.
     */
    public Mono<SurvivalVerdict> checkSurvival(byte[] servedBytes, String mode, String size) {
        if (http == null) return Mono.just(new SurvivalVerdict(false, null, "no worker"));
        return http.post()
                .uri("/survival")
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .header("X-Cloak-Mode", mode)
                .header("X-Cloak-Size", size == null ? "original" : size)
                .bodyValue(servedBytes)
                .retrieve()
                .bodyToMono(SurvivalVerdict.class)
                .timeout(jobTimeout)
                .map(v -> v == null ? new SurvivalVerdict(false, null, "empty verdict") : v)
                .onErrorResume(e -> {
                    log.warn("[poison-worker] survival check failed (mode={}, size={}): {}", mode, size, e.toString());
                    return Mono.just(new SurvivalVerdict(false, null, "check error"));
                });
    }
}
