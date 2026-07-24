package systems.hugmesh.userbff.media;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

/**
 * The closed set of AI-cloak {@code mode} kinds the media-proxy honours — the REQUESTED
 * perturbation strength a user picks when uploading an image. This is a genuinely CLOSED
 * vocabulary: it is pinned by the 007 {@code media_poison_decision.mode} DB CHECK and the
 * legacy {@link MediaPoisonDecision#validMode(String)} guard — both of which accept
 * exactly {@code glaze | nightshade | light | none}. NOTE: the durable user preference
 * {@code media.poison.default} speaks the USER-FACING
 * {@code systems.hugmesh.userbff.prefstore.MediaPoisonMode} vocabulary
 * ({@code off|low|medium|high}) which maps 1:1 onto this engine set — this enum stays
 * the ENGINE/pipeline vocabulary only.
 *
 * <h2>Wire form is BYTE-IDENTICAL to the prior {@code String}</h2>
 * Each constant carries the EXACT lowercase token the system has always stored /
 * exchanged (mirroring federation #46 {@code ScopeKind}):
 * <ul>
 *   <li><b>DB</b> — the {@code media_poison_decision.mode varchar} column keeps its
 *       lowercase strings. {@link MediaPoisonDecisionEntity#mode()} still persists a
 *       {@code String}, so R2DBC reads/writes are unchanged; this enum is a CODE-SIDE
 *       lens over that string, never a column-type change.</li>
 *   <li><b>JSON</b> — {@link #value()} is annotated {@link JsonValue}, so the enum emits
 *       the lowercase token (not the Java constant name); {@link #fromWire(String)} (also
 *       a {@link JsonCreator}) parses the same tokens back. The DTOs ({@link
 *       MediaPoisonDecision#mode()}) still bind {@code mode} as a {@code String}, so this
 *       is not on a current JSON path — but the round-trip is wire-safe by construction.</li>
 * </ul>
 */
public enum CloakMode {

    /** Glaze-style cloak (style-mimicry defence). */
    GLAZE("glaze"),
    /** Nightshade-style cloak (data-poisoning defence). */
    NIGHTSHADE("nightshade"),
    /** Light CPU-tier cloak (the lean path a present worker offers). */
    LIGHT("light"),
    /** Opt-out — forward the bytes through unchanged (status {@code none}). */
    NONE("none");

    private final String value;

    CloakMode(String value) {
        this.value = value;
    }

    /** The exact lowercase wire token ({@code glaze | nightshade | light | none}). */
    @JsonValue
    public String value() {
        return value;
    }

    /**
     * Parse a wire token to its {@link CloakMode}, or {@code null} when the token is
     * null / unrecognised. Null-tolerant by design so it can replace the {@code String}
     * equality checks without ever throwing on a stray value.
     */
    @JsonCreator
    public static CloakMode fromWire(String wire) {
        if (wire == null) {
            return null;
        }
        for (CloakMode m : values()) {
            if (m.value.equals(wire)) {
                return m;
            }
        }
        return null;
    }

    /**
     * True iff {@code wire} is one of the four valid mode tokens — the typed equivalent
     * of the legacy {@link MediaPoisonDecision#validMode(String)} guard, so callers that
     * still hold a raw {@code String} get the same accept/reject verdict.
     */
    public static boolean isValid(String wire) {
        return fromWire(wire) != null;
    }
}
