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
}
