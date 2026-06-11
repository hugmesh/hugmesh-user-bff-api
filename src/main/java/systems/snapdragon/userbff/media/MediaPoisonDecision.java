package systems.snapdragon.userbff.media;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.time.Instant;

/**
 * One AI-cloak decision belonging to the caller (table {@code media_poison_decision}).
 * This is the SERVER-OWNED source of truth for what the BFF media-proxy did to an
 * uploaded image: the chosen {@code mode}, the honest {@code status} outcome, and the
 * {@code backend} that ran — the audit trail, the badge source, and the repost source
 * of truth.
 *
 * <p>{@code userId} is the owner = the Casdoor JWT subject and is NEVER accepted from
 * the request body (the controller always sets it from the JWT subject), so a user
 * cannot record/read a decision under another user.
 *
 * <p>Vocabularies (DB-paralleled by the 007 CHECK constraints):
 * <ul>
 *   <li>{@code platform} — {@code matrix|mastodon};</li>
 *   <li>{@code mode} — {@code glaze|nightshade|light|none} (the requested cloak);</li>
 *   <li>{@code status} — {@code protected|degraded|skipped|none|pending|failed}.
 *       HONEST: {@code protected} ONLY after the post-ingest survival gate passes;
 *       {@code degraded} when the cloak washed out; {@code skipped} when the worker
 *       was absent and bytes were forwarded UNCLOAKED; {@code none} on opt-out /
 *       non-image;</li>
 *   <li>{@code backend} — {@code cuda|rocm|cpu|none} (the worker backend that ran).</li>
 * </ul>
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record MediaPoisonDecision(
        String id,
        String userId,
        String platform,
        String mediaRef,
        String mode,
        String status,
        String backend,
        Instant createdAt) {

    /** The homeserver platforms an upload can target. */
    public static boolean validPlatform(String p) {
        return "matrix".equals(p) || "mastodon".equals(p);
    }

    /** The requestable cloak modes (incl. {@code none} = opt-out / forward-through). */
    public static boolean validMode(String m) {
        return "glaze".equals(m) || "nightshade".equals(m) || "light".equals(m) || "none".equals(m);
    }

    /** The honest status outcomes the badge renders from. */
    public static boolean validStatus(String s) {
        return "protected".equals(s) || "degraded".equals(s) || "skipped".equals(s)
                || "none".equals(s) || "pending".equals(s) || "failed".equals(s);
    }
}
