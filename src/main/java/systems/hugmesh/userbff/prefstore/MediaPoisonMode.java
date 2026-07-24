package systems.hugmesh.userbff.prefstore;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import systems.hugmesh.userbff.media.CloakMode;

/**
 * The USER-FACING vocabulary of the durable {@code media.poison.default} preference —
 * the AI-cloak intensity a user picks in the preferences panel. THIS BFF IS THE SOURCE
 * OF TRUTH for the contract: the wire vocabulary is exactly
 * {@code off | low | medium | high} (the {@code MediaPoisonMode} union the paired
 * hugmesh-user-ui preferences panel speaks), and it is exported to clients through
 * the committed OpenAPI spec's {@code MediaPoisonMode} schema so a UI can never drift
 * from it silently again (the pre-contract drift left the panel 400-ing on every save).
 *
 * <p>Each user-facing intensity maps 1:1 onto the ENGINE vocabulary the cloak pipeline
 * runs ({@link CloakMode}, {@code glaze|nightshade|light|none} — the 007 DB CHECK, the
 * per-upload {@code mode} part, the poison-worker contract; all UNCHANGED):
 *
 * <ul>
 *   <li>{@code off}    ↔ {@link CloakMode#NONE} — no cloaking by default;</li>
 *   <li>{@code low}    ↔ {@link CloakMode#LIGHT} — subtle CPU-tier noise;</li>
 *   <li>{@code medium} ↔ {@link CloakMode#GLAZE} — moderate (the recommended
 *       default, mirroring the server's {@code glaze} policy default);</li>
 *   <li>{@code high}   ↔ {@link CloakMode#NIGHTSHADE} — aggressive noise.</li>
 * </ul>
 *
 * <p>The preference STORE persists the user-facing token; only the resolution seam
 * ({@link UserPreferencesService}) translates: the server policy default (an engine
 * token from {@code MediaPoisoningProperties}) is translated to user-facing on the
 * defaults merge, and any legacy engine token still sitting in a durable row is
 * canonicalised on read — so the resolved view ALWAYS speaks {@code off|low|medium|high}.
 */
public enum MediaPoisonMode {

    /** No AI-cloaking by default (engine {@code none}). */
    OFF("off", CloakMode.NONE),
    /** Subtle adversarial noise (engine {@code light}). */
    LOW("low", CloakMode.LIGHT),
    /** Moderate noise — the recommended default (engine {@code glaze}). */
    MEDIUM("medium", CloakMode.GLAZE),
    /** Aggressive noise (engine {@code nightshade}). */
    HIGH("high", CloakMode.NIGHTSHADE);

    /** The full user-facing vocabulary, for validation messages and docs. */
    public static final String VOCABULARY = "off|low|medium|high";

    private final String value;
    private final CloakMode engineMode;

    MediaPoisonMode(String value, CloakMode engineMode) {
        this.value = value;
        this.engineMode = engineMode;
    }

    /** The exact lowercase wire token ({@code off | low | medium | high}). */
    @JsonValue
    public String value() {
        return value;
    }

    /** The engine-side cloak mode this intensity maps onto ({@link CloakMode}). */
    public CloakMode engineMode() {
        return engineMode;
    }

    /**
     * Parse a USER-FACING wire token to its {@link MediaPoisonMode}, or {@code null}
     * when the token is null / unrecognised (null-tolerant so validation sites can
     * reject with a clean 400 instead of throwing).
     */
    @JsonCreator
    public static MediaPoisonMode fromWire(String wire) {
        if (wire == null) {
            return null;
        }
        for (MediaPoisonMode m : values()) {
            if (m.value.equals(wire)) {
                return m;
            }
        }
        return null;
    }

    /** True iff {@code wire} is one of the four valid user-facing tokens. */
    public static boolean isValid(String wire) {
        return fromWire(wire) != null;
    }

    /**
     * Translate an ENGINE token ({@code glaze|nightshade|light|none}) to its user-facing
     * mode, or {@code null} when the token is not a recognised engine token. Used to
     * surface the server policy default — and any legacy stored engine value — in the
     * contract vocabulary.
     */
    public static MediaPoisonMode fromEngineToken(String engineToken) {
        CloakMode engine = CloakMode.fromWire(engineToken);
        if (engine == null) {
            return null;
        }
        for (MediaPoisonMode m : values()) {
            if (m.engineMode == engine) {
                return m;
            }
        }
        return null; // unreachable — every CloakMode has a user-facing mapping
    }
}
