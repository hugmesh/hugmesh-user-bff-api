package systems.hugmesh.userbff.profile;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferLimitException;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.codec.multipart.FilePart;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;
import systems.hugmesh.commons.web.ApiException;
import systems.hugmesh.userbff.media.ImageSniffer;
import systems.hugmesh.userbff.security.PrincipalDomain;

import java.util.Map;

/**
 * Owner-scoped profile endpoints. The owner is ALWAYS the JWT subject
 * ({@code jwt.getSubject()}) — never a path/body field — so a user can only ever
 * read/write their OWN profile. ROLE_USER floor (enforced by SecurityConfig path
 * rules) + {@code @PreAuthorize("hasRole('USER')")} defence-in-depth.
 *
 * <p>There is deliberately NO {@code /profile/{userId}} route: the only profile a
 * caller can address is their own, identified by the token.
 */
@Tag(name = "Profile", description = "The caller's OWN profile (owner = JWT subject). Password/email go to the Casdoor IdP.")
@RestController
@RequestMapping("/bff/user/profile")
@PreAuthorize("hasRole('USER')")
@Validated
public class ProfileController {

    /** Maximum accepted avatar upload size — 5 MB. Larger uploads are rejected with
     *  400 before the bytes are read into memory in full. */
    private static final long MAX_AVATAR_BYTES = 5L * 1024 * 1024;

    private final ProfileService profiles;
    private final AvatarService avatars;
    private final PrincipalDomain principalDomain;

    public ProfileController(ProfileService profiles, AvatarService avatars,
                             PrincipalDomain principalDomain) {
        this.profiles = profiles;
        this.avatars = avatars;
        this.principalDomain = principalDomain;
    }

    /** Change-password body (typed + validated; was an untyped Map). The IdP
     *  enforces the password policy; we only require non-blank fields here. */
    public record PasswordChangeRequest(
            String oldPassword,
            @NotBlank(message = "newPassword is required")
            @Size(min = 1, max = 256, message = "newPassword must be 1-256 chars") String newPassword) {}

    /** Change-email body (typed + validated; was an untyped Map). */
    public record EmailChangeRequest(
            @NotBlank(message = "email is required")
            @Email(message = "email must be a valid address")
            @Size(max = 320, message = "email must be at most 320 chars") String email) {}

    @Operation(summary = "Get my profile (owner = JWT subject).")
    @GetMapping
    public Mono<UserProfile> me(@AuthenticationPrincipal Jwt jwt) {
        return profiles.get(jwt.getSubject(), principalDomain.forScope(jwt));
    }

    @Operation(summary = "Create/update my profile. The body's userId is ignored — the owner is the JWT subject; the vanity username is derived from the token.")
    @PutMapping
    public Mono<UserProfile> upsert(@AuthenticationPrincipal Jwt jwt, @Valid @RequestBody UserProfile body) {
        // owner = JWT SUBJECT (the row key); username = the vanity DNS label, derived
        // from the token (NOT the body) so the reserved-username guard can't be
        // bypassed by spoofing the body.
        return profiles.save(jwt.getSubject(), usernameOf(jwt), body, principalDomain.forScope(jwt));
    }

    @Operation(summary = "Upload my profile picture (multipart 'file'). The bytes are stored on "
            + "the Matrix homeserver media repo (stub-gated) and the mxc:// URL is saved on my "
            + "profile; the refreshed profile is returned. Owner = JWT subject.")
    @PostMapping(value = "/avatar", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public Mono<UserProfile> uploadAvatar(@AuthenticationPrincipal Jwt jwt,
                                          @RequestPart("file") FilePart file) {
        String owner = jwt.getSubject();
        String domain = principalDomain.forScope(jwt);
        String contentType = contentTypeOf(file);
        // Cheap first gate on the client header — a part not even CLAIMING to be an image
        // is a 400 before any bytes are read. The authoritative check is the magic-byte
        // sniff below (the header is attacker-controlled and is never trusted on its own).
        if (contentType == null || !contentType.toLowerCase().startsWith("image/")) {
            return Mono.error(ApiException.badRequest(
                    "profile picture must be an image (Content-Type image/*)"));
        }
        // Read the multipart bytes (enforcing the 5 MB cap), then require the bytes to be a
        // REAL raster image by magic bytes (rejects SVG/HTML/polyglots labeled image/* —
        // the stored-XSS gap) and forward the SNIFFED type, never the client header. Only
        // after both gates pass is anything stored; then return the REFRESHED profile.
        // The refreshed-profile read is DEFERRED so it is assembled only after a successful
        // store — an upstream 400 (oversize / non-image bytes) short-circuits here and is
        // never overtaken by the read.
        return readCappedBytes(file)
                .flatMap(bytes -> storeSniffedImage(owner, bytes, domain))
                .then(Mono.defer(() -> profiles.get(owner, domain)));
    }

    /**
     * Magic-byte gate + store. The client {@code Content-Type} is NOT trusted: the bytes
     * must sniff to a known raster image ({@link ImageSniffer}, which deliberately rejects
     * SVG), else a 400 with NO upload attempted. The SNIFFED type is the stored/forwarded
     * Content-Type.
     */
    private Mono<String> storeSniffedImage(String owner, byte[] bytes, String domain) {
        String sniffed = ImageSniffer.detect(bytes);
        if (sniffed == null) {
            return Mono.error(ApiException.badRequest(
                    "profile picture must be a real image (magic-byte check failed)"));
        }
        return avatars.uploadAndStore(owner, bytes, sniffed, domain);
    }

    /** The declared Content-Type of the uploaded part, or null when absent. */
    private static String contentTypeOf(FilePart file) {
        MediaType type = file.headers().getContentType();
        return type == null ? null : type.toString();
    }

    /**
     * Read the multipart file's content into a {@code byte[]}, rejecting (400) any
     * upload larger than {@link #MAX_AVATAR_BYTES}. The cap is enforced AT the join
     * (bounded by {@code MAX_AVATAR_BYTES + 1}) so an oversize part overflows the join
     * as a {@link DataBufferLimitException} — mapped to a clean 400 — instead of being
     * buffered unbounded or surfacing as a 500. Mirrors the
     * {@code MediaPoisonController.readBounded} idiom.
     */
    private static Mono<byte[]> readCappedBytes(FilePart file) {
        return DataBufferUtils.join(file.content(),
                        (int) Math.min(MAX_AVATAR_BYTES + 1, Integer.MAX_VALUE))
                .flatMap(ProfileController::toCappedByteArray)
                .onErrorMap(ProfileController::isJoinLimit, ProfileController::oversizeBadRequest);
    }

    /** Convert a joined {@link DataBuffer} to a capped {@code byte[]}, releasing the
     *  buffer; fail with 400 when it exceeds the cap. */
    private static Mono<byte[]> toCappedByteArray(DataBuffer joined) {
        int size = joined.readableByteCount();
        if (size > MAX_AVATAR_BYTES) {
            DataBufferUtils.release(joined);
            return Mono.error(oversizeBadRequest(null));
        }
        byte[] bytes = new byte[size];
        joined.read(bytes);
        DataBufferUtils.release(joined);
        return Mono.just(bytes);
    }

    /** The join's size cap overflows as a {@link DataBufferLimitException}. */
    private static boolean isJoinLimit(Throwable t) {
        return t instanceof DataBufferLimitException;
    }

    /** The canonical oversize-avatar 400 (size cap exceeded). */
    private static ApiException oversizeBadRequest(Throwable ignored) {
        return ApiException.badRequest(
                "profile picture exceeds the " + (MAX_AVATAR_BYTES / (1024 * 1024)) + "MB limit");
    }

    /**
     * The caller's USERNAME for vanity purposes, derived from the JWT. Casdoor mints
     * the {@code preferred_username} claim = the user's login name (the DNS label
     * behind {@code <username>.hugmesh.systems}); we fall back to {@code name},
     * then to the subject only if neither claim is present. This is the documented
     * single home for "how the username is obtained from the token".
     */
    static String usernameOf(Jwt jwt) {
        String preferred = jwt.getClaimAsString("preferred_username");
        if (preferred != null && !preferred.isBlank()) {
            return preferred;
        }
        String name = jwt.getClaimAsString("name");
        if (name != null && !name.isBlank()) {
            return name;
        }
        return jwt.getSubject();
    }

    @Operation(summary = "Delete my profile.")
    @DeleteMapping
    public Mono<ResponseEntity<Void>> delete(@AuthenticationPrincipal Jwt jwt) {
        return profiles.delete(jwt.getSubject(), principalDomain.forScope(jwt))
                .thenReturn(ResponseEntity.noContent().build());
    }

    @Operation(summary = "Change my Casdoor password (goes to the IdP, not the profile table).")
    @PostMapping("/password")
    public Mono<Map<String, Object>> changePassword(@AuthenticationPrincipal Jwt jwt,
                                                    @Valid @RequestBody PasswordChangeRequest body) {
        return profiles.changePassword(jwt.getSubject(), body.oldPassword(), body.newPassword())
                .thenReturn(ack("password-change", profiles.casdoorEnabled()));
    }

    @Operation(summary = "Change my Casdoor email (goes to the IdP, not the profile table).")
    @PostMapping("/email")
    public Mono<Map<String, Object>> changeEmail(@AuthenticationPrincipal Jwt jwt,
                                                 @Valid @RequestBody EmailChangeRequest body) {
        return profiles.changeEmail(jwt.getSubject(), body.email())
                .thenReturn(ack("email-change", profiles.casdoorEnabled()));
    }

    /** Acknowledgement carrying whether the live Casdoor write ran or was stubbed. */
    private static Map<String, Object> ack(String op, boolean live) {
        return Map.of("op", op, "status", live ? "submitted" : "queued",
                "casdoor", live ? "live" : "stubbed");
    }
}
