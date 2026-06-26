package systems.snapdragon.userbff.profile;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import systems.snapdragon.commons.web.ApiException;

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

    public AvatarService(MatrixMediaClient matrixMedia, UserProfileRepository repo,
                         EdgeAiAnalysisClient moderation) {
        this.matrixMedia = matrixMedia;
        this.repo = repo;
        this.moderation = moderation;
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
                return Mono.<String>error(ApiException.unprocessable(
                        "profile picture blocked by content policy"));
            }
            return matrixMedia.upload(owner, bytes, contentType)
                    .flatMap(mxc -> repo.updateAvatarUrl(owner, mxc, domain).thenReturn(mxc));
        });
    }
}
