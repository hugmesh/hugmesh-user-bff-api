package net.hugmesh.userbff.media;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import net.hugmesh.userbff.web.PlatformKind;

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

    /** Accept iff {@code p} is a valid external platform token — the closed
     *  {@code matrix|mastodon} set is now modelled by {@link PlatformKind}; this guard
     *  delegates to it so there is ONE source of truth (behaviour byte-identical). */
    public static boolean validPlatform(String p) {
        return PlatformKind.isValid(p);
    }

    /** Accept iff {@code m} is a valid cloak-mode token — the closed
     *  {@code glaze|nightshade|light|none} set is now modelled by {@link CloakMode};
     *  this guard delegates to it so there is ONE source of truth. */
    public static boolean validMode(String m) {
        return CloakMode.isValid(m);
    }

    /** Accept iff {@code s} is a valid status token — the closed
     *  {@code protected|degraded|skipped|none|pending|failed} set is now modelled by
     *  {@link PoisonStatus}; this guard delegates to it so there is ONE source of truth. */
    public static boolean validStatus(String s) {
        return PoisonStatus.isValid(s);
    }
}
