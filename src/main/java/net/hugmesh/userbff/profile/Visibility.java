package net.hugmesh.userbff.profile;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

/**
 * The closed set of {@code user_profile.visibility} kinds — WHO may see a profile. This
 * is a genuinely CLOSED 2-value vocabulary: it is pinned by the 005
 * {@code ck_user_profile_visibility} DB CHECK, the {@code ValidationPatterns.VISIBILITY}
 * bean-validation regex on {@link UserProfile#visibility()}, and the
 * {@link UserProfile#DEFAULT_VISIBILITY} floor, all of which accept exactly
 * {@code public | internal}.
 *
 * <h2>Wire form is BYTE-IDENTICAL to the prior {@code String}</h2>
 * Each constant carries the EXACT lowercase token the system has always stored /
 * exchanged (mirroring federation #46 {@code ScopeKind}):
 * <ul>
 *   <li><b>DB</b> — the {@code user_profile.visibility varchar} column keeps its
 *       lowercase strings; {@link UserProfile#visibility()} still persists a
 *       {@code String}. This enum is a CODE-SIDE lens, never a column-type change.</li>
 *   <li><b>JSON</b> — {@link #value()} ({@link JsonValue}) emits the lowercase token;
 *       {@link #fromWire(String)} ({@link JsonCreator}) parses it back. The DTO still
 *       binds {@code visibility} as a {@code String} (the {@code @Pattern} stays the
 *       request-time guard), so this is not on a current JSON path — but the round-trip
 *       is wire-safe by construction.</li>
 * </ul>
 */
public enum Visibility {

    /** Visible beyond the platform (the user opted in). */
    PUBLIC("public"),
    /** Private to the platform — the default floor unless the user opts in. */
    INTERNAL("internal");

    private final String value;

    Visibility(String value) {
        this.value = value;
    }

    /** The exact lowercase wire token ({@code public | internal}) — the DB/JSON form. */
    @JsonValue
    public String value() {
        return value;
    }

    /**
     * Parse a wire token to its {@link Visibility}, or {@code null} when the token is
     * null / unrecognised. Null-tolerant by design so it can stand in for the
     * {@code String} equality checks without ever throwing on a stray value.
     */
    @JsonCreator
    public static Visibility fromWire(String wire) {
        if (wire == null) {
            return null;
        }
        for (Visibility v : values()) {
            if (v.value.equals(wire)) {
                return v;
            }
        }
        return null;
    }

    /** True iff {@code wire} is one of the two valid visibility tokens. */
    public static boolean isValid(String wire) {
        return fromWire(wire) != null;
    }
}
