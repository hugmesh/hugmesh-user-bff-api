package systems.snapdragon.userbff.block;

import reactor.core.publisher.Mono;

/**
 * Pushes a user's self-block out to an external platform (Matrix / Mastodon). One
 * implementation per platform. The call is reactive (never blocks the event loop)
 * and best-effort at the service layer — the durable {@code user_block} row is the
 * source of truth even if the external push is stubbed or fails.
 */
public interface ExternalBlockClient {

    /** {@code "matrix"} or {@code "mastodon"} — matches {@code user_block.platform}. */
    String platform();

    /**
     * Push the block of {@code target} on behalf of the owning user
     * ({@code ownerUserId} = the caller's JWT subject / platform handle). Returns
     * whether a LIVE external call was made (false = documented stub / disabled).
     */
    Mono<Boolean> block(String ownerUserId, String target);
}
