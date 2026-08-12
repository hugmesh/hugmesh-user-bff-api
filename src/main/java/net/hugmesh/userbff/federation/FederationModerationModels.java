package net.hugmesh.userbff.federation;

/**
 * Request/response shapes for the federation-api moderation surface, matched
 * field-for-field to {@code ModerationController.SubmitRequest} in
 * hugmesh-federation-api.
 */
public final class FederationModerationModels {

    private FederationModerationModels() {}

    /**
     * The body federation-api's {@code POST /api/federation/moderation} expects:
     * {@code (kind, target, reason)}. The {@code status} is NOT a request field —
     * federation-api sets it to {@code recommended} server-side on submit.
     *
     * <p><b>NOT used by the recommend-instance-block flow.</b> That surface is
     * {@code ROLE_MOD}/{@code ROLE_ADMIN}/{@code ROLE_SUPERADMIN}-gated at
     * federation-api (a mod/admin's own submit) — a plain
     * {@code ROLE_MATRIX}/{@code ROLE_MASTODON} user forwarded here would always
     * 403 (this WAS the bug; see {@link #RecommendInstanceBlockRequest} below for
     * the fix). Currently used only by {@link FederationApiClient
     * #requestSelfSilenceReactivation}.
     */
    public record SubmitRequest(String kind, String target, String reason) {}

    /**
     * The body federation-api's narrower, self-service {@code POST
     * /api/federation/moderation/recommend-instance-block} expects:
     * {@code (target, reason)} — deliberately NO {@code kind} field, matched
     * field-for-field to {@code ModerationController.RecommendInstanceBlockRequest}
     * in hugmesh-federation-api. {@code kind} is hardcoded server-side to
     * {@code instance-block}; {@code status} likewise server-side to
     * {@code recommended}.
     *
     * <p><b>Root-cause fix</b>: {@code BlockController.recommendInstanceBlock}
     * requires only {@code ROLE_MATRIX}/{@code ROLE_MASTODON} and forwards the
     * caller's own bearer unmodified to federation-api. It used to POST to the
     * mod-only {@code /api/federation/moderation} ({@code SubmitRequest}), whose
     * path-level gate ({@code hasAnyRole('MOD','ADMIN','SUPERADMIN')}) NO
     * {@code RoleHierarchy} edge lets a plain platform participant pass — so the
     * ONE caller who could ever legitimately reach this BFF endpoint always got
     * 403'd downstream, end-to-end unreachable. federation-api added this narrower
     * surface (exactly {@code ROLE_MATRIX}/{@code ROLE_MASTODON}, nothing wider —
     * NOT list/refer/decide) rather than widening the mod-only gate, because the
     * mod-only surface is deliberately staff-only (its javadoc: "the mod's Casdoor
     * subject", "ROLE_MOD, ROLE_ADMIN, or ROLE_SUPERADMIN may submit") and every
     * OTHER real caller of it ({@code hugmesh-mod-bff-api}) is itself
     * {@code hasAnyRole('MOD','ADMIN')}-gated.
     *
     * @see FederationApiClient#recommendInstanceBlock(String, String)
     */
    public record RecommendInstanceBlockRequest(String target, String reason) {}

    /**
     * The body federation-api's {@code POST /api/federation/findings} expects, matched
     * field-for-field to {@code SystemFindingController.FileRequest} in
     * hugmesh-federation-api: {@code (surface, disposition, classification,
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
