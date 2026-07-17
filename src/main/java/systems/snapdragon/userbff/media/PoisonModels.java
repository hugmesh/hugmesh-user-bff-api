package systems.snapdragon.userbff.media;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonValue;

import java.util.List;

/**
 * The DTOs that cross the BFF&lt;-&gt;{@code snapdragon-media-poisoner} worker boundary
 * and the in-BFF result types the {@link MediaPoisonService} orchestrates over. Kept
 * in one file (small, cohesive, no behaviour) so the worker contract is read in one
 * place; the Jackson-bound ones get native hints in {@code NativeHintsConfig}.
 */
public final class PoisonModels {

    private PoisonModels() {}

    /**
     * The compute backend the worker reports it is running (capability + honesty) — the
     * closed {@code cuda|rocm|cpu|none} set the worker {@code /health} probe reports.
     *
     * <p>This enum PREDATES the federation #46 {@code ScopeKind} convention and already
     * served as the code-side lens over the {@code String backend} wire/DB token; it is
     * now ALIGNED to that shape — {@link #value()} ({@link JsonValue}) and
     * {@link #fromWire(String)} ({@link JsonCreator}) emit/parse the IDENTICAL lowercase
     * tokens. The pre-existing {@link #parse(String)} / {@link #wire()} are kept as
     * BEHAVIOUR-PRESERVING aliases so every call site is unchanged: {@code parse} keeps
     * its NONE-default-and-trim leniency (the worker /health string may be padded /
     * absent), whereas {@code fromWire} is the strict null-on-unknown JSON creator
     * matching the sibling enums. Wire/DB tokens stay byte-identical either way.
     */
    public enum Backend {
        CUDA("cuda"), ROCM("rocm"), CPU("cpu"), NONE("none");

        private final String value;

        Backend(String value) {
            this.value = value;
        }

        /** The exact lowercase wire token ({@code cuda|rocm|cpu|none}) — equals {@link #wire()}. */
        @JsonValue
        public String value() {
            return value;
        }

        /**
         * Strict JSON parse: an exact lowercase token to its {@link Backend}, or
         * {@code null} for null / unrecognised — the #46-shaped creator (mirrors the
         * sibling {@code CloakMode}/{@code PoisonStatus}/{@code PlatformKind}). For the
         * lenient worker-/health path use {@link #parse(String)} instead.
         */
        @JsonCreator
        public static Backend fromWire(String wire) {
            if (wire == null) {
                return null;
            }
            for (Backend b : values()) {
                if (b.value.equals(wire)) {
                    return b;
                }
            }
            return null;
        }

        /** Lenient parse for the worker {@code /health} string: null / unknown / padded
         *  ⇒ {@link #NONE} (heavy tier absent). Behaviour unchanged from the original. */
        public static Backend parse(String s) {
            if (s == null) return NONE;
            return switch (s.trim().toLowerCase()) {
                case "cuda" -> CUDA;
                case "rocm" -> ROCM;
                case "cpu" -> CPU;
                default -> NONE;
            };
        }

        /** The lowercase wire token — retained alias of {@link #value()}. */
        public String wire() { return value; }

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
    public record Health(String backend, List<String> modes, Integer etaSeconds) {
        // Copy on the way IN: the accessor below can only hand out a safe view if the
        // field itself is not still the caller's (mutable) list. Null is preserved
        // rather than normalised so the record's equals/hashCode shape is unchanged.
        public Health {
            modes = modes == null ? null : List.copyOf(modes);
        }

        // Return a defensive copy so callers cannot mutate the internal list.
        @Override
        public List<String> modes() {
            return modes == null ? List.of() : List.copyOf(modes);
        }
    }

    /**
     * A poison job submitted to the worker: the original image bytes (base64 on the
     * wire), the requested {@code mode}, and the served thumbnail sizes to ALSO poison
     * so no clean derivative exists ({@code akkoma "small"}; Matrix 240x240 — pinned by
     * config). The worker returns the poisoned original + each poisoned size.
     */
    public record PoisonRequest(String mode, String filename, String contentType,
                                List<String> thumbnailSizes, byte[] imageBase64NotUsed) {
        // Copy on the way IN — without this the caller retains a live reference to the
        // image bytes / size list and can mutate this record's state after construction.
        public PoisonRequest {
            thumbnailSizes = thumbnailSizes == null ? null : List.copyOf(thumbnailSizes);
            imageBase64NotUsed = imageBase64NotUsed == null ? null : imageBase64NotUsed.clone();
        }

        // Return defensive copies so callers cannot mutate the internal mutable fields.
        @Override
        public List<String> thumbnailSizes() {
            return thumbnailSizes == null ? List.of() : List.copyOf(thumbnailSizes);
        }

        @Override
        public byte[] imageBase64NotUsed() {
            return imageBase64NotUsed == null ? null : imageBase64NotUsed.clone();
        }
    }

    /**
     * The worker's poison result: the poisoned original + a per-size poisoned
     * derivative, plus the backend that ran. {@code ok=false} (or a non-2xx) means the
     * worker could not cloak — the service records {@code failed} / falls back. Sizes
     * key the derivatives map (e.g. {@code "small"}, {@code "240x240"}).
     */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record PoisonResult(boolean ok, String backend, byte[] poisonedOriginal,
                               List<SizedBytes> thumbnails, String detail) {
        // Copy on the way IN — the poisoned bytes must not stay aliased to the buffer
        // the worker-response decoder handed us.
        public PoisonResult {
            poisonedOriginal = poisonedOriginal == null ? null : poisonedOriginal.clone();
            thumbnails = thumbnails == null ? null : List.copyOf(thumbnails);
        }

        // Return defensive copies so callers cannot mutate the internal mutable fields.
        @Override
        public byte[] poisonedOriginal() {
            return poisonedOriginal == null ? null : poisonedOriginal.clone();
        }

        @Override
        public List<SizedBytes> thumbnails() {
            return thumbnails == null ? List.of() : List.copyOf(thumbnails);
        }
    }

    /** One poisoned derivative for a served size. */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record SizedBytes(String size, byte[] bytes) {
        // Copy on the way IN so the derivative's bytes cannot be mutated post-construction.
        public SizedBytes {
            bytes = bytes == null ? null : bytes.clone();
        }

        // Return a defensive copy so callers cannot mutate the internal byte array.
        @Override
        public byte[] bytes() {
            return bytes == null ? null : bytes.clone();
        }
    }

    /**
     * The worker's perturbation-presence verdict for ONE re-fetched served artifact
     * (original or a thumbnail) — the round-trip survival gate's per-artifact answer.
     * {@code present=true} means the cloak signal survived the homeserver re-encode.
     */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record SurvivalVerdict(boolean present, Double score, String detail) {}
}
