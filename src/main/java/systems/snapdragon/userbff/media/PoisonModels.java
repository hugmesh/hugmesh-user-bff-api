package systems.snapdragon.userbff.media;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

/**
 * The DTOs that cross the BFF&lt;-&gt;{@code snapdragon-media-poisoner} worker boundary
 * and the in-BFF result types the {@link MediaPoisonService} orchestrates over. Kept
 * in one file (small, cohesive, no behaviour) so the worker contract is read in one
 * place; the Jackson-bound ones get native hints in {@code NativeHintsConfig}.
 */
public final class PoisonModels {

    private PoisonModels() {}

    /** The compute backend the worker reports it is running (capability + honesty). */
    public enum Backend {
        CUDA, ROCM, CPU, NONE;

        public static Backend parse(String s) {
            if (s == null) return NONE;
            return switch (s.trim().toLowerCase()) {
                case "cuda" -> CUDA;
                case "rocm" -> ROCM;
                case "cpu" -> CPU;
                default -> NONE;
            };
        }

        public String wire() { return name().toLowerCase(); }

        /** Whether the worker can actually run a cloak (any backend but NONE). */
        public boolean present() { return this != NONE; }
    }

    /**
     * The worker {@code /health} probe response. {@code backend} is the live compute
     * tier; {@code modes} is what the worker offers; {@code etaSeconds} a coarse
     * per-image estimate the UI badge renders. A non-2xx / absent endpoint is treated
     * by {@link PoisonWorkerClient#capability()} as {@code backend=none} (heavy tier
     * absent) WITHOUT this object — so the lean fallback engages.
     */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Health(String backend, List<String> modes, Integer etaSeconds) {}

    /**
     * A poison job submitted to the worker: the original image bytes (base64 on the
     * wire), the requested {@code mode}, and the served thumbnail sizes to ALSO poison
     * so no clean derivative exists ({@code akkoma "small"}; Matrix 240x240 — pinned by
     * config). The worker returns the poisoned original + each poisoned size.
     */
    public record PoisonRequest(String mode, String filename, String contentType,
                                List<String> thumbnailSizes, byte[] imageBase64NotUsed) {}

    /**
     * The worker's poison result: the poisoned original + a per-size poisoned
     * derivative, plus the backend that ran. {@code ok=false} (or a non-2xx) means the
     * worker could not cloak — the service records {@code failed} / falls back. Sizes
     * key the derivatives map (e.g. {@code "small"}, {@code "240x240"}).
     */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record PoisonResult(boolean ok, String backend, byte[] poisonedOriginal,
                               List<SizedBytes> thumbnails, String detail) {}

    /** One poisoned derivative for a served size. */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record SizedBytes(String size, byte[] bytes) {}

    /**
     * The worker's perturbation-presence verdict for ONE re-fetched served artifact
     * (original or a thumbnail) — the round-trip survival gate's per-artifact answer.
     * {@code present=true} means the cloak signal survived the homeserver re-encode.
     */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record SurvivalVerdict(boolean present, Double score, String detail) {}
}
