package systems.hugmesh.userbff.media;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

/**
 * The closed set of HONEST cloak-outcome {@code status} kinds the media-proxy records —
 * the server-owned verdict for what actually happened to an uploaded image. This is a
 * genuinely CLOSED vocabulary: it is pinned by the 007 {@code media_poison_decision.status}
 * DB CHECK and the legacy {@link MediaPoisonDecision#validStatus(String)} guard, both of
 * which accept exactly {@code protected | degraded | skipped | none | pending | failed}.
 *
 * <h2>Wire form is BYTE-IDENTICAL to the prior {@code String}</h2>
 * Each constant carries the EXACT lowercase token the system has always stored /
 * exchanged (mirroring federation #46 {@code ScopeKind}):
 * <ul>
 *   <li><b>DB</b> — the {@code media_poison_decision.status varchar} column keeps its
 *       lowercase strings. {@link MediaPoisonDecisionEntity#status()} still persists a
 *       {@code String}; this enum is a CODE-SIDE lens, never a column-type change.</li>
 *   <li><b>JSON</b> — {@link #value()} ({@link JsonValue}) emits the lowercase token;
 *       {@link #fromWire(String)} ({@link JsonCreator}) parses it back. The DTO
 *       ({@link MediaPoisonDecision#status()}) still binds {@code status} as a
 *       {@code String}, so this is not on a current JSON path — but the round-trip is
 *       wire-safe by construction.</li>
 * </ul>
 *
 * <p>Semantics (the honesty contract): {@link #PROTECTED} ONLY after the post-ingest
 * survival gate passes; {@link #DEGRADED} when the cloak washed out; {@link #SKIPPED}
 * when the worker was absent and bytes were forwarded UNCLOAKED; {@link #NONE} on opt-out
 * / non-image; {@link #PENDING}/{@link #FAILED} the async/worker-failure outcomes.
 */
public enum PoisonStatus {

    /** Cloak verified surviving the homeserver re-encode (the only honest "protected"). */
    PROTECTED("protected"),
    /** Cloak washed out — the perturbation did not survive the round-trip. */
    DEGRADED("degraded"),
    /** Worker absent — bytes forwarded UNCLOAKED (the UI warns "not cloaked"). */
    SKIPPED("skipped"),
    /** Opt-out / non-image — nothing to cloak. */
    NONE("none"),
    /** Recorded but not yet resolved (an async-in-flight outcome). */
    PENDING("pending"),
    /** Worker failed — the ORIGINAL was forwarded (never a false "protected"). */
    FAILED("failed");

    private final String value;

    PoisonStatus(String value) {
        this.value = value;
    }

    /** The exact lowercase wire token (the DB/JSON form). */
    @JsonValue
    public String value() {
        return value;
    }

    /**
     * Parse a wire token to its {@link PoisonStatus}, or {@code null} when the token is
     * null / unrecognised. Null-tolerant by design so it can stand in for the
     * {@code String} equality checks without ever throwing on a stray value.
     */
    @JsonCreator
    public static PoisonStatus fromWire(String wire) {
        if (wire == null) {
            return null;
        }
        for (PoisonStatus s : values()) {
            if (s.value.equals(wire)) {
                return s;
            }
        }
        return null;
    }

    /**
     * True iff {@code wire} is one of the six valid status tokens — the typed equivalent
     * of the legacy {@link MediaPoisonDecision#validStatus(String)} guard.
     */
    public static boolean isValid(String wire) {
        return fromWire(wire) != null;
    }
}
