package systems.hugmesh.userbff.web;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

/**
 * The closed set of EXTERNAL homeserver {@code platform} kinds the user-BFF talks to —
 * the {@code matrix | mastodon} discriminator that recurs across the media-proxy
 * decision, the connected-client audit, and the homeserver service-token custody. This
 * is a genuinely CLOSED vocabulary: it is pinned by the 007 {@code media_poison_decision}
 * CHECK and the legacy {@code validPlatform} guards on {@link
 * systems.hugmesh.userbff.media.MediaPoisonDecision} /
 * {@link systems.hugmesh.userbff.client.ConnectedClient}, plus the
 * {@code HsServiceTokenRow.PLATFORM_MATRIX/PLATFORM_MASTODON} discriminators — all of
 * which accept exactly {@code matrix | mastodon}.
 *
 * <p>NOTE: this is the EXTERNAL-homeserver platform set ONLY. The {@code user_block}
 * platform additionally allows {@code internal} (platform-local blocks); that 3-value
 * set is modelled separately by {@code block.BlockPlatform} so this shared lens stays the
 * pure {@code matrix|mastodon} pair its three call sites share. The dynamic / open sets
 * ({@code ROLE_MATRIX}/{@code ROLE_MASTODON} authorities, {@code DOMAIN_<brand>} brands,
 * free-form role grants) are NOT modelled here — they stay {@code String} per the standard.
 *
 * <h2>Wire form is BYTE-IDENTICAL to the prior {@code String}</h2>
 * Each constant carries the EXACT lowercase token the system has always stored /
 * exchanged (mirroring federation #46 {@code ScopeKind}):
 * <ul>
 *   <li><b>DB</b> — every {@code platform varchar} column keeps its lowercase strings;
 *       the entities still persist a {@code String}, so R2DBC reads/writes are unchanged.
 *       This enum is a CODE-SIDE lens, never a column-type change.</li>
 *   <li><b>JSON</b> — {@link #value()} ({@link JsonValue}) emits the lowercase token;
 *       {@link #fromWire(String)} ({@link JsonCreator}) parses it back. The DTOs still
 *       bind {@code platform} as a {@code String}, so this is not on a current JSON
 *       path — but the round-trip is wire-safe by construction.</li>
 * </ul>
 */
public enum PlatformKind {

    /** A Matrix homeserver (tuwunel / Synapse-compatible). */
    MATRIX("matrix"),
    /** A Mastodon-API homeserver (akkoma). */
    MASTODON("mastodon");

    private final String value;

    PlatformKind(String value) {
        this.value = value;
    }

    /** The exact lowercase wire token ({@code matrix | mastodon}) — the DB/JSON form. */
    @JsonValue
    public String value() {
        return value;
    }

    /**
     * Parse a wire token to its {@link PlatformKind}, or {@code null} when the token is
     * null / unrecognised. Null-tolerant by design so it can stand in for the
     * {@code String} equality checks without ever throwing on a stray value.
     */
    @JsonCreator
    public static PlatformKind fromWire(String wire) {
        if (wire == null) {
            return null;
        }
        for (PlatformKind p : values()) {
            if (p.value.equals(wire)) {
                return p;
            }
        }
        return null;
    }

    /**
     * True iff {@code wire} is one of the two valid platform tokens — the typed
     * equivalent of the legacy {@code validPlatform(String)} guards, so callers that
     * still hold a raw {@code String} get the same accept/reject verdict.
     */
    public static boolean isValid(String wire) {
        return fromWire(wire) != null;
    }
}
