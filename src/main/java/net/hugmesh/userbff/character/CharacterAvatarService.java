package net.hugmesh.userbff.character;

import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import net.hugmesh.userbff.media.ImageSniffer;
import net.hugmesh.userbff.profile.UserProfileRepository;

import java.util.Set;

/**
 * Resolve + serve the VN CHARACTER AVATAR: the profile picture as it is rendered inside
 * OTHER users' forum posts.
 *
 * <p><b>Why this exists next to the owner-scoped avatar serve.</b>
 * {@code GET /bff/user/profile/avatar/body} resolves the owner from the JWT subject, so
 * the URL is identical for every caller and always returns the CALLER's own picture.
 * That is exactly right for "show me my avatar" and unusable for the VN sprite, which
 * renders the POST AUTHOR's image in a READER's browser — the same URL there would show
 * the reader their own face on everyone's posts. The forum VN profile therefore has to
 * store a ref that names WHOSE avatar, and it cannot name it by subject: a Casdoor
 * subject is routinely a {@code provider:handle} composite carrying an e-mail, which is
 * neither URL-path-safe nor fit to publish in every reader's access log — and the
 * forum-bff allowlist guarding the stored value has neither {@code :} nor {@code @} in
 * its charset.
 *
 * <p>So the avatar gets an OPAQUE, STABLE handle (023 {@code user_profile.avatar_ref},
 * minted lazily on first use, never rotated) and is served at
 * {@code GET /bff/user/character/avatar/{ref}/body}.
 *
 * <p><b>Access rule — deliberately the same shape as the sticker serve</b>
 * ({@link StickerService#serveBody}), because it is the same job: media that must render
 * inside other users' posts. The owner always; any other caller only within the SAME
 * brand (or an unscoped SUPERADMIN caller). There is no PENDING/ACTIVE ladder to mirror
 * because an avatar cannot be stored un-moderated — {@code AvatarService.uploadAndStore}
 * runs the edge-AI gate BEFORE persisting and a blocked image is never written, so any
 * row that has pixels has already passed. Every refusal — unknown handle, malformed
 * handle, cross-brand, no stored pixels, non-raster stored type — is the SAME empty
 * result, which the controller renders as one uniform 404: nothing here may reveal that
 * some other user's handle exists.
 *
 * <p><b>The raster gate is not decoration.</b> These bytes now leave the owner's own
 * browser and land in an {@code <img>} in everyone else's, so a stored
 * {@code image/svg+xml} would be cross-user stored XSS. SVG can't get in — the upload
 * path magic-byte-sniffs and {@link ImageSniffer} rejects vectors outright — and
 * {@link #SERVEABLE_TYPES} keeps it that way from the READ side too, so no future write
 * path, migration or hand-edited row can turn this route into an XSS delivery channel.
 * Never widen it to a vector type.
 */
@Service
public class CharacterAvatarService {

    /**
     * The MIME types this route will serve — exactly the raster set
     * {@link ImageSniffer#detect(byte[])} can produce, which is the only thing the
     * avatar upload path is able to record. Anything else (notably
     * {@code image/svg+xml}) is treated as a miss. Kept as an explicit allowlist rather
     * than "whatever is stored" so the SVG rejection holds on the read side as well as
     * the write side; {@code CharacterAvatarServiceTest} pins it to ImageSniffer's real
     * output so the two can never drift apart.
     */
    static final Set<String> SERVEABLE_TYPES =
            Set.of("image/jpeg", "image/png", "image/gif", "image/webp", "image/bmp");

    /** The MIME served for a row whose sniffed type was never recorded (pre-022 rows
     *  carry no pixels at all, so this is belt-and-braces; PNG is the sticker/avatar
     *  serve floor used everywhere else in this BFF). */
    static final String DEFAULT_TYPE = "image/png";

    private final UserProfileRepository profiles;

    public CharacterAvatarService(UserProfileRepository profiles) {
        this.profiles = profiles;
    }

    /**
     * The CALLER's own stable serve handle, minted on first use.
     *
     * @param owner  the caller's JWT subject.
     * @param domain the caller's brand ({@code null} = SUPERADMIN cross-domain bypass).
     * @return the handle, or EMPTY when the caller has no stored avatar pixels (a
     *         handle for an empty slot would only publish a ref that 404s).
     */
    public Mono<String> refForOwner(String owner, String domain) {
        // Gate on the PIXELS, not the profile row: a user who never uploaded gets a 404
        // and no handle is minted for them.
        return profiles.findAvatarBody(owner, domain)
                .flatMap(body -> profiles.ensureAvatarRef(owner, domain));
    }

    /**
     * The avatar bytes behind a serve handle, subject to the access rule above.
     *
     * @param ref           the opaque serve handle from the URL (already charset-gated
     *                      by the controller).
     * @param caller        the requesting user's JWT subject.
     * @param callerDomain  the requesting user's brand ({@code null} = unscoped
     *                      SUPERADMIN caller).
     * @return the pixels + the MIME to serve them as, or EMPTY on ANY miss.
     */
    public Mono<AvatarBody> serveBody(String ref, String caller, String callerDomain) {
        return profiles.findAvatarBodyByRef(ref)
                .filter(row -> servesTo(row, caller, callerDomain))
                .map(row -> new AvatarBody(row.bytes(), serveType(row.contentType())))
                .filter(body -> SERVEABLE_TYPES.contains(body.contentType()));
    }

    /**
     * The serve access decision: the OWNER always; anyone else only from the same brand
     * (or an unscoped SUPERADMIN caller). Mirrors
     * {@code StickerService.servesTo}'s ACTIVE branch — an avatar with stored pixels has
     * already cleared the upload-time moderation gate, so there is no pending state to
     * hold it back.
     */
    private static boolean servesTo(UserProfileRepository.AvatarBodyForRef row,
                                    String caller, String callerDomain) {
        boolean isOwner = row.owner() != null && row.owner().equals(caller);
        return isOwner || callerDomain == null || callerDomain.equals(row.domain());
    }

    /** The stored sniffed type, or the PNG floor when a row records none. */
    private static String serveType(String stored) {
        return stored == null || stored.isBlank() ? DEFAULT_TYPE : stored;
    }

    /** Pixels + the MIME type to serve them as (already allowlist-checked). */
    public record AvatarBody(byte[] bytes, String contentType) { }
}
