package net.hugmesh.userbff.block;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

/**
 * The closed set of {@code user_block.platform} kinds — the WHERE a self-block applies.
 * This extends the external {@code matrix | mastodon} pair with {@code internal} (a
 * platform-local block). It is a genuinely CLOSED vocabulary: it is pinned by the 005
 * {@code user_block.platform} DB CHECK, the {@code ValidationPatterns.PLATFORM} bean-
 * validation regex, and the legacy {@link UserBlock#validPlatform(String)} guard, all of
 * which accept exactly {@code matrix | mastodon | internal}.
 *
 * <p>This is kept separate from the shared {@code web.PlatformKind} (the pure
 * {@code matrix|mastodon} external-homeserver lens) precisely because the block
 * vocabulary adds {@code internal}; folding {@code internal} into the shared lens would
 * widen the external-platform contract.
 *
 * <h2>Wire form is BYTE-IDENTICAL to the prior {@code String}</h2>
 * Each constant carries the EXACT lowercase token the system has always stored /
 * exchanged (mirroring federation #46 {@code ScopeKind}):
 * <ul>
 *   <li><b>DB</b> — the {@code user_block.platform varchar} column keeps its lowercase
 *       strings; the entity still persists a {@code String}. This enum is a CODE-SIDE
 *       lens, never a column-type change.</li>
 *   <li><b>JSON</b> — {@link #value()} ({@link JsonValue}) emits the lowercase token;
 *       {@link #fromWire(String)} ({@link JsonCreator}) parses it back. The DTO
 *       ({@link UserBlock#platform()}) still binds {@code platform} as a {@code String},
 *       so this is not on a current JSON path — but the round-trip is wire-safe.</li>
 * </ul>
 */
public enum BlockPlatform {

    /** A Matrix homeserver identity. */
    MATRIX("matrix"),
    /** A Mastodon-API homeserver identity. */
    MASTODON("mastodon"),
    /** A platform-local (internal) identity — no external homeserver. */
    INTERNAL("internal");

    private final String value;

    BlockPlatform(String value) {
        this.value = value;
    }

    /** The exact lowercase wire token ({@code matrix | mastodon | internal}). */
    @JsonValue
    public String value() {
        return value;
    }

    /**
     * Parse a wire token to its {@link BlockPlatform}, or {@code null} when the token is
     * null / unrecognised. Null-tolerant by design so it can stand in for the
     * {@code String} equality checks without ever throwing on a stray value.
     */
    @JsonCreator
    public static BlockPlatform fromWire(String wire) {
        if (wire == null) {
            return null;
        }
        for (BlockPlatform p : values()) {
            if (p.value.equals(wire)) {
                return p;
            }
        }
        return null;
    }

    /**
     * True iff {@code wire} is one of the three valid block-platform tokens — the typed
     * equivalent of the legacy {@link UserBlock#validPlatform(String)} guard.
     */
    public static boolean isValid(String wire) {
        return fromWire(wire) != null;
    }
}
