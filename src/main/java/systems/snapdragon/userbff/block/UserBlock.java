package systems.snapdragon.userbff.block;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.time.Instant;

/**
 * One self-block belonging to the caller (table {@code user_block}). {@code userId}
 * is the owner = the Casdoor JWT subject; {@code target} is the blocked identity;
 * {@code platform} is {@code matrix|mastodon|internal}. A user only ever sees/edits
 * their own blocks (owner-enforcement in {@code BlockService}).
 *
 * <p>{@code userId} is never accepted from the request body — the controller always
 * sets it from the JWT subject, so a user cannot create a block under another user.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record UserBlock(
        String id,
        String userId,
        String target,
        String platform,
        Instant ts) {

    /** Allowed external platforms (plus 'internal' for platform-local blocks). */
    public static boolean validPlatform(String p) {
        return "matrix".equals(p) || "mastodon".equals(p) || "internal".equals(p);
    }
}
