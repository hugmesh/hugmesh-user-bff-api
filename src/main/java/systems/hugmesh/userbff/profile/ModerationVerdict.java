package systems.hugmesh.userbff.profile;

/**
 * The verdict from the on-prem edge-AI content-moderation service
 * ({@code POST /v1/analyze/content/moderate}) for a profile picture.
 *
 * @param action         {@code allow} | {@code flag} | {@code reject} — the service's
 *                       policy decision (it applies its own NSFW/abuse thresholds)
 * @param classification {@code safe} | {@code nsfw} | {@code abuse} | {@code unknown}
 * @param confidence     0.0–1.0 model confidence
 * @param policyHit      true iff a policy class was hit at/over threshold
 * @param perceptualHash hex pHash (kept for audit / future hash-blocklist); may be null
 */
public record ModerationVerdict(String action, String classification, double confidence,
                                boolean policyHit, String perceptualHash) {

    /** Feature OFF (no edge-AI moderation node) — let the image through unchanged. */
    public static ModerationVerdict allow() {
        return new ModerationVerdict("allow", "safe", 0.0, false, null);
    }

    /** Fail-CLOSED sentinel — the scanner was supposed to run but couldn't, so the
     *  image must NOT go live (treated as blocked). */
    public static ModerationVerdict reject(String why) {
        return new ModerationVerdict("reject", why, 1.0, true, null);
    }

    /**
     * Whether this verdict BLOCKS the avatar from going live. In this first slice both
     * {@code reject} and {@code flag} block (fail-closed: a flagged image is not published
     * until the human-review queue exists — see the A3b follow-up). Only {@code allow} passes.
     */
    public boolean blocks() {
        return !"allow".equalsIgnoreCase(action == null ? "" : action);
    }
}
