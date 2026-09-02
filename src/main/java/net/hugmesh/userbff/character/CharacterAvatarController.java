package net.hugmesh.userbff.character;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.CacheControl;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;
import net.hugmesh.commons.web.ApiException;
import net.hugmesh.userbff.security.PrincipalDomain;

import java.util.regex.Pattern;

/**
 * The VN CHARACTER AVATAR surface — the profile picture as a forum-post sprite, served
 * to the READERS of a post rather than only to its owner.
 *
 * <ul>
 *   <li>GET {@code /bff/user/character/avatar} — MY stable serve handle plus the URL
 *       built from it. This is the value hugmesh-forum-ui stores as the forum VN
 *       profile's {@code characterImgRef}. 404 when I have no stored picture (nothing
 *       to point at), which the UI feature-detects to hide the "use my avatar" option;</li>
 *   <li>GET {@code /bff/user/character/avatar/{ref}/body} — the pixels behind a handle.
 *       NOT owner-scoped on purpose: an avatar chosen as a VN sprite has to render
 *       inside OTHER users' posts, exactly like an ACTIVE sticker. The access rule and
 *       the raster-only gate live in {@link CharacterAvatarService}; every miss —
 *       malformed handle, unknown handle, cross-brand caller, no stored pixels — is
 *       one uniform 404, so the route never reveals that someone else's handle exists.</li>
 * </ul>
 *
 * <p>ROLE_USER floor (SecurityConfig path rules on {@code /bff/user/**}) +
 * {@code @PreAuthorize("hasRole('USER')")} defence-in-depth, mirroring
 * {@link StickerController}. The handle is unguessable and is published by its owner
 * (into their own VN profile) — it is the capability; the domain check is what stops it
 * crossing brands.
 *
 * <p>This closes hugmesh-forum-bff-api issue #3: the forum VN editor used to store the
 * literal path {@code /bff/user/character/avatar}, which had no route behind it in this
 * BFF at all, so every avatar-mode VN profile rendered a broken image.
 */
@Tag(name = "Character-avatar", description = "The profile picture as a VN forum sprite: "
        + "the caller's own stable serve handle, and the raster bytes behind a handle "
        + "(readable by other users in the same brand so a sprite renders in their posts).")
@RestController
@RequestMapping("/bff/user/character/avatar")
@PreAuthorize("hasRole('USER')")
@Validated
public class CharacterAvatarController {

    /** The handle shape: a lowercase-hex UUID (36 chars). Gated here so a value that
     *  could not possibly be a handle never reaches the store, and so the shape stays
     *  inside the forum-bff {@code characterImgRef} charset
     *  ({@code [A-Za-z0-9._/-]}) — no percent-encoding, no {@code ..}, nothing that
     *  changes meaning in a URL path. */
    private static final Pattern REF_SHAPE =
            Pattern.compile("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}");

    private final CharacterAvatarService service;
    private final PrincipalDomain principalDomain;

    public CharacterAvatarController(CharacterAvatarService service, PrincipalDomain principalDomain) {
        this.service = service;
        this.principalDomain = principalDomain;
    }

    /**
     * MY serve handle and the same-origin URL built from it.
     *
     * @param ref the opaque, stable handle for my avatar slot.
     * @param url the {@code /bff/user/character/avatar/{ref}/body} path to render as an
     *        {@code <img src>} — returned assembled so the ONE place that knows how the
     *        URL is spelled is this server, not every client.
     */
    public record CharacterAvatarRef(String ref, String url) {}

    @Operation(summary = "My VN character-avatar serve handle + its image URL (the value to "
            + "store as a forum VN profile characterImgRef). 404 when I have no stored profile "
            + "picture. Owner = JWT subject.")
    @GetMapping
    public Mono<CharacterAvatarRef> myRef(@AuthenticationPrincipal Jwt jwt) {
        return service.refForOwner(jwt.getSubject(), principalDomain.forScope(jwt))
                .map(ref -> new CharacterAvatarRef(ref, bodyUrl(ref)))
                .switchIfEmpty(Mono.error(ApiException.notFound("no character avatar")));
    }

    @Operation(summary = "Serve the raster bytes behind a character-avatar handle. Readable by "
            + "the owner and by other users in the same brand (a VN sprite has to render inside "
            + "their posts); any miss — malformed/unknown handle, cross-brand caller, no stored "
            + "pixels, non-raster stored type — is a uniform 404.")
    @GetMapping("/{ref}/body")
    public Mono<ResponseEntity<byte[]>> serveBody(@AuthenticationPrincipal Jwt jwt,
                                                  @PathVariable String ref) {
        // Charset gate FIRST: a value that cannot be a handle is the SAME uniform 404 as
        // an unknown one — no separate 400 that would leak which misses were well-formed.
        if (ref == null || !REF_SHAPE.matcher(ref).matches()) {
            return Mono.error(ApiException.notFound("character avatar not found"));
        }
        return service.serveBody(ref, jwt.getSubject(), principalDomain.forScope(jwt))
                .map(CharacterAvatarController::asImageResponse)
                .switchIfEmpty(Mono.error(ApiException.notFound("character avatar not found")));
    }

    /** The same-origin body URL for a handle — the single spelling of this route. */
    static String bodyUrl(String ref) {
        return "/bff/user/character/avatar/" + ref + "/body";
    }

    /**
     * Wrap the stored pixels with the same hardened headers the sticker and owner-scoped
     * avatar serves use: the SNIFFED MIME recorded at upload (never a client-declared
     * one), {@code nosniff} so the bytes can never be re-interpreted as a document,
     * and a locked-down CSP.
     *
     * <p>{@code Cache-Control: no-store}: the handle is STABLE across re-uploads (a VN
     * profile stores it, so it must not rotate), which means the URL alone cannot tell a
     * URL-keyed browser cache that the pixels changed. A freshness window here would
     * keep serving a replaced — or moderator-removed — picture to every reader of every
     * post. Same conclusion the sticker and profile-avatar serves reached, for the same
     * reason.
     */
    private static ResponseEntity<byte[]> asImageResponse(CharacterAvatarService.AvatarBody body) {
        return ResponseEntity.ok()
                .contentType(MediaType.parseMediaType(body.contentType()))
                .header("X-Content-Type-Options", "nosniff")
                .header("Content-Security-Policy", "default-src 'none'")
                .header("Content-Disposition", "inline")
                .cacheControl(CacheControl.noStore())
                .body(body.bytes());
    }
}
