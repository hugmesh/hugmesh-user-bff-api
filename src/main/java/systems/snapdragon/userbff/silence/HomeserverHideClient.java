package systems.snapdragon.userbff.silence;

import reactor.core.publisher.Mono;

/**
 * SELF-SILENCE homeserver VISIBILITY/DISCOVERY hide seam — one implementation per
 * platform (akkoma = Mastodon, tuwunel = Matrix). Hides the user from DISCOVERY
 * (directory listing / discoverability) while they are self-silenced, and un-hides
 * on expiry/cancel.
 *
 * <p>This is purely a discovery/visibility flag — NEVER a suspend / deactivate /
 * token-invalidating action (that is a ban, a different surface entirely). The user
 * keeps their session and full access throughout; only their findability changes.
 *
 * <p>GATED STUB-SEAM (scope-guard): defaults OFF
 * ({@code external.<platform>.enabled=false}); when disabled every call is a
 * documented stub that returns {@code false} (no live call) and NEVER hard-fails —
 * the durable {@code self_silence} row is the source of truth and the real admin
 * verbs (akkoma discoverable=false; tuwunel exclude-from-directory via the
 * admin-room bot — Conduit-family has no REST admin API) get wired/pinned later.
 */
public interface HomeserverHideClient {

    /** {@code "matrix"} or {@code "mastodon"} — the platform this seam hides on. */
    String platform();

    /**
     * Hide {@code localpart} from the platform's directory/discovery. Returns whether
     * a LIVE call was made ({@code false} = documented stub / disabled). Fail-closed
     * for the silence flow at the service layer: a failed/stubbed hide never hard-
     * fails activation; the row + scheduled retry converge.
     */
    Mono<Boolean> hide(String localpart);

    /** Reverse of {@link #hide(String)} — un-hide / re-list {@code localpart}. */
    Mono<Boolean> unhide(String localpart);
}
