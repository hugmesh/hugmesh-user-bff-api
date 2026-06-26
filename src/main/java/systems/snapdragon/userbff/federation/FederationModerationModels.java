package systems.snapdragon.userbff.federation;

/**
 * Request/response shapes for the federation-api moderation surface, matched
 * field-for-field to {@code ModerationController.SubmitRequest} in
 * snapdragon-federation-api.
 */
public final class FederationModerationModels {

    private FederationModerationModels() {}

    /**
     * The body federation-api's {@code POST /api/federation/moderation} expects:
     * {@code (kind, target, reason)}. The {@code status} is NOT a request field —
     * federation-api sets it to {@code recommended} server-side on submit. For the
     * user recommend-instance-block flow, {@code kind="instance-block"} and
     * {@code target} is the instance (homeserver/domain) being recommended for a
     * block.
     */
    public record SubmitRequest(String kind, String target, String reason) {}

    /**
     * The body federation-api's {@code POST /api/federation/findings} expects, matched
     * field-for-field to {@code SystemFindingController.FileRequest} in
     * snapdragon-federation-api: {@code (surface, disposition, classification,
     * confidence, policyHit, perceptualHash)}.
     *
     * <p>The {@code subject} is NOT a request field — federation-api derives it
     * server-side from the FORWARDED bearer (the caller's JWT subject), so a user can
     * only ever file a finding ABOUT THEMSELVES. {@code reporter="@system"} and
     * {@code status="held"} are likewise stamped server-side. {@code disposition} must
     * be {@code flagged} (queued for human review) | {@code rejected} (hard-blocked).
     * The optional fields ({@code classification}, {@code confidence}, {@code policyHit},
     * {@code perceptualHash}) carry the edge-AI verdict for the moderator's context.
     *
     * <p>{@code subjectRef} (federation-api #70, optional) is an opaque PRODUCER-side
     * back-reference — the id of the user-bff row (a {@code vn_character_part} /
     * {@code vn_sticker_pack} id) that filed this finding. federation-api echoes it back
     * unchanged so the later admin-bff reconciler can tell this BFF, when the finding is
     * resolved, WHICH row to flip. It is NOT the moderation subject (that stays the
     * forwarded JWT subject) — it is a convenience link, so it is nullable and ignored by
     * surfaces that don't set it.
     */
    public record FindingRequest(String surface, String disposition, String classification,
                                 Double confidence, Boolean policyHit, String perceptualHash,
                                 String subjectRef) {}
}
