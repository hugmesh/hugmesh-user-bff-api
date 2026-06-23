package systems.snapdragon.userbff.profile;

import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

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

    private final MatrixMediaClient matrixMedia;
    private final UserProfileRepository repo;

    public AvatarService(MatrixMediaClient matrixMedia, UserProfileRepository repo) {
        this.matrixMedia = matrixMedia;
        this.repo = repo;
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
        // 1) upload to the homeserver media repo (stub-gated) -> mxc:// URL;
        // 2) persist the mxc:// onto the owner's avatar_url; 3) return the mxc://.
        return matrixMedia.upload(owner, bytes, contentType)
                .flatMap(mxc -> repo.updateAvatarUrl(owner, mxc, domain).thenReturn(mxc));
    }
}
