package systems.hugmesh.userbff.client;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

/**
 * The closed set of {@code connected_client_audit.client_kind} kinds — WHAT a connected
 * credential is: an OAuth application grant or a login-device session. This is a
 * genuinely CLOSED 2-value vocabulary, previously half-modelled as the
 * {@code ConnectedClient.KIND_OAUTH_APP}/{@code KIND_DEVICE} {@code String} constants and
 * the legacy {@link ConnectedClient#validKind(String)} guard, both of which accept
 * exactly {@code oauth-app | device}.
 *
 * <h2>Wire form is BYTE-IDENTICAL to the prior {@code String}</h2>
 * Each constant carries the EXACT lowercase token the system has always stored /
 * exchanged (mirroring federation #46 {@code ScopeKind}); note the {@code oauth-app}
 * token carries an internal hyphen — preserved verbatim:
 * <ul>
 *   <li><b>DB</b> — the {@code connected_client_audit.client_kind varchar} column keeps
 *       its lowercase strings; {@link ConnectedClient#clientKind()} still persists a
 *       {@code String}. This enum is a CODE-SIDE lens, never a column-type change.</li>
 *   <li><b>JSON</b> — {@link #value()} ({@link JsonValue}) emits the lowercase token;
 *       {@link #fromWire(String)} ({@link JsonCreator}) parses it back. The DTO still
 *       binds {@code clientKind} as a {@code String}, so this is not on a current JSON
 *       path — but the round-trip is wire-safe by construction.</li>
 * </ul>
 */
public enum ClientKind {

    /** A native OAuth application grant (Element / Tusky / Ivory). */
    OAUTH_APP("oauth-app"),
    /** A login-device session registered against the homeserver. */
    DEVICE("device");

    private final String value;

    ClientKind(String value) {
        this.value = value;
    }

    /** The exact lowercase wire token ({@code oauth-app | device}) — the DB/JSON form. */
    @JsonValue
    public String value() {
        return value;
    }

    /**
     * Parse a wire token to its {@link ClientKind}, or {@code null} when the token is
     * null / unrecognised. Null-tolerant by design so it can stand in for the
     * {@code String} equality checks without ever throwing on a stray value.
     */
    @JsonCreator
    public static ClientKind fromWire(String wire) {
        if (wire == null) {
            return null;
        }
        for (ClientKind k : values()) {
            if (k.value.equals(wire)) {
                return k;
            }
        }
        return null;
    }

    /**
     * True iff {@code wire} is one of the two valid client-kind tokens — the typed
     * equivalent of the legacy {@link ConnectedClient#validKind(String)} guard.
     */
    public static boolean isValid(String wire) {
        return fromWire(wire) != null;
    }
}
