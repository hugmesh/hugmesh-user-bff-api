package net.hugmesh.userbff.profile;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import net.hugmesh.commons.web.ApiException;
import net.hugmesh.userbff.federation.FederationApiClient;
import net.hugmesh.userbff.federation.FederationModerationModels.FindingRequest;

/**
 * Owner-enforced profile-picture (avatar) upload. The flow is:
 * <ol>
 *   <li>upload the image bytes to the Matrix homeserver media repository via
 *       {@link MatrixMediaClient} (STUB-GATED — a stub {@code mxc://} is returned when
 *       the live homeserver upload is disabled, so the feature ships dark);</li>
 *   <li>persist the returned {@code mxc://} URL onto the OWNER's profile row
 *       ({@code user_profile.avatar_url}) via {@link UserProfileRepository}, owner AND
 *       domain scoped — never another user's / brand's row;</li>
 *   <li>return the {@code mxc://} URL.</li>
 * </ol>
 *
 * <p>{@code owner} is the caller's JWT subject (passed by the controller from the
 * validated token) — a user can only ever set their OWN avatar. The image bytes are
 * never logged.
 */
@Service
public class AvatarService {

    private static final Logger log = LoggerFactory.getLogger(AvatarService.class);

    private final MatrixMediaClient matrixMedia;
    private final UserProfileRepository repo;
    private final EdgeAiAnalysisClient moderation;
    private final FederationApiClient federation;

    public AvatarService(MatrixMediaClient matrixMedia, UserProfileRepository repo,
                         EdgeAiAnalysisClient moderation, FederationApiClient federation) {
        this.matrixMedia = matrixMedia;
        this.repo = repo;
        this.moderation = moderation;
        this.federation = federation;
    }

    /**
     * Upload the owner's profile picture and store its {@code mxc://} URL on their
     * profile.
     *
     * @param owner       the caller's JWT subject (the owner row key); must be non-blank.
     * @param bytes       the raw image bytes (never logged).
     * @param contentType the image MIME type.
     * @param domain      the caller's validated-issuer brand ({@code null} = SUPERADMIN
     *                    cross-domain bypass).
     * @return the stored {@code mxc://} URL.
     * @throws IllegalArgumentException if {@code owner} is null/blank.
     */
    public Mono<String> uploadAndStore(String owner, byte[] bytes, String contentType, String domain) {
        if (owner == null || owner.isBlank()) {
            throw new IllegalArgumentException("owner (JWT subject) is required");
        }
        // 0) edge-AI vision moderation BEFORE publish (dark by default ⇒ allow; FAIL-CLOSED
        //    when enabled-but-unreachable). A blocked image never reaches the homeserver and
        //    is never persisted. Bytes are never logged — only the policy verdict.
        // 1) upload to the homeserver media repo (stub-gated) -> mxc:// URL;
        // 2) persist the mxc:// onto the owner's avatar_url; 3) return the mxc://.
        return moderation.moderate(bytes).flatMap(verdict -> {
            if (verdict.blocks()) {
                log.info("[avatar] BLOCKED by content policy: action={} class={} confidence={} owner={}",
                        verdict.action(), verdict.classification(), verdict.confidence(), owner);
                // A3 producer: file the blocked image into the federation @system findings
                // queue so a moderator can review it (held). BEST-EFFORT — the image is
                // blocked regardless; a federation outage must not change the user-facing
                // 422, so a file failure is logged and swallowed. The caller's bearer is
                // forwarded by FederationApiClient, so federation derives subject = owner.
                return fileHeldFinding(owner, verdict)
                        .then(Mono.<String>error(ApiException.unprocessable(
                                "profile picture blocked by content policy")));
            }
            // The MODERATED bytes are persisted alongside the homeserver ref, in the
            // same statement (022). Until they were, this service uploaded to a
            // stub-gated homeserver client and then DISCARDED the pixels, so the row
            // held `mxc://stub.invalid/<uuid-of-owner>` — a ref to no image — and
            // every avatar rendered broken. `contentType` here is the SNIFFED type
            // the controller resolved, never the client-declared header.
            return matrixMedia.upload(owner, bytes, contentType)
                    .flatMap(mxc -> repo.updateAvatarUrl(owner, mxc, domain, bytes, contentType)
                            .thenReturn(mxc));
        });
    }

    /**
     * File a blocked avatar verdict into the federation {@code @system} findings queue
     * (held, for moderator review). Fail-soft: a federation error is logged and swallowed
     * (the image stays blocked either way). The edge-AI {@code action} ({@code flag} |
     * {@code reject}) maps to the federation {@code disposition} ({@code flagged} |
     * {@code rejected}); {@code surface="profile-avatar"}.
     */
    private Mono<Void> fileHeldFinding(String owner, ModerationVerdict verdict) {
        String disposition = "reject".equalsIgnoreCase(verdict.action()) ? "rejected" : "flagged";
        // subjectRef=null: the avatar is stored on the profile row, not a moderated-queue
        // row keyed by finding — there is no part/sticker id to back-link the finding to.
        FindingRequest req = new FindingRequest(
                "profile-avatar", disposition, verdict.classification(),
                verdict.confidence(), verdict.policyHit(), verdict.perceptualHash(), null);
        return federation.fileFinding(req)
                .doOnNext(r -> log.info("[avatar] finding filed (held) for owner={} disposition={}", owner, disposition))
                .onErrorResume(e -> {
                    log.warn("[avatar] finding-file FAILED (image still blocked) owner={}: {}", owner, e.toString());
                    return Mono.empty();
                })
                .then();
    }
}
