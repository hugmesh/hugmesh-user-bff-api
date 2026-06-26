package systems.snapdragon.userbff.character;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.snapdragon.commons.web.ApiException;
import systems.snapdragon.userbff.security.PrincipalDomain;

/**
 * Owner-scoped endpoints for USER-DRAWN character PARTS (the VN/character-studio
 * drawable-parts feature). The owner is ALWAYS the JWT subject
 * ({@code jwt.getSubject()}) — never a path/body field — so a user can only ever
 * save/list/serve their OWN parts. ROLE_USER floor (enforced by SecurityConfig path
 * rules on {@code /bff/user/**}) + {@code @PreAuthorize("hasRole('USER')")}
 * defence-in-depth.
 *
 * <ul>
 *   <li>POST {@code /bff/user/character/parts} — save a part: the body's dirty SVG is
 *       SANITIZED ({@link systems.snapdragon.userbff.svg.SvgSanitizerService}) before
 *       storage (a malformed/non-svg body is a 422), stored {@code status=PENDING}, and
 *       a held {@code @system} moderation finding is filed. Returns the part metadata;</li>
 *   <li>GET {@code /bff/user/character/parts} — list MY parts (newest first);</li>
 *   <li>GET {@code /bff/user/character/parts/{id}/svg} — serve MY stored SANITIZED svg
 *       owner-scoped, with HARDENED headers (image/svg+xml + a locked-down CSP +
 *       nosniff + inline). A foreign id is a 404 (not 403) — no cross-owner existence
 *       leak.</li>
 * </ul>
 */
@Tag(name = "Character-parts", description = "The caller's OWN user-drawn character parts "
        + "(owner = JWT subject). SVG is server-sanitized before storage and reviewed by a moderator.")
@RestController
@RequestMapping("/bff/user/character/parts")
@PreAuthorize("hasRole('USER')")
@Validated
public class CharacterPartController {

    /**
     * Hardened CSP for serving a stored part SVG as an IMAGE: no scripts/network at all
     * ({@code default-src 'none'}), inline styles only (SVG presentation), and
     * {@code sandbox} to neutralise any residual active content. Defence-in-depth on top
     * of the sanitizer — the bytes are served as an image, never as inline HTML.
     */
    private static final String SVG_CSP = "default-src 'none'; style-src 'unsafe-inline'; sandbox";

    private final CharacterPartService service;
    private final PrincipalDomain principalDomain;

    public CharacterPartController(CharacterPartService service, PrincipalDomain principalDomain) {
        this.service = service;
        this.principalDomain = principalDomain;
    }

    /** Save-a-part body (typed + validated). The owner is the JWT subject, NOT the body;
     *  the {@code svg} is the dirty client SVG (sanitized server-side before storage). */
    public record SavePartRequest(
            @Size(max = 120, message = "name must be at most 120 chars") String name,
            @Size(max = 40, message = "headArchetype must be at most 40 chars") String headArchetype,
            @NotBlank(message = "svg is required")
            @Size(max = 1_000_000, message = "svg must be at most 1,000,000 chars") String svg) {}

    @Operation(summary = "Save a user-drawn character part. The SVG is server-sanitized "
            + "(a malformed/non-svg body is a 422), stored status=PENDING, and queued for "
            + "moderation. Owner = JWT subject.")
    @PostMapping
    public Mono<VnCharacterPart> save(@AuthenticationPrincipal Jwt jwt,
                                      @Valid @RequestBody SavePartRequest body) {
        // owner = JWT SUBJECT (the row key) — never a body field; domain = the
        // issuer-derived brand. The service sanitizes the SVG before anything is stored.
        return service.savePart(jwt.getSubject(), principalDomain.forScope(jwt),
                body.name(), body.headArchetype(), body.svg());
    }

    @Operation(summary = "List MY character parts (newest first). Owner = JWT subject.")
    @GetMapping
    public Flux<VnCharacterPart> listMine(@AuthenticationPrincipal Jwt jwt) {
        return service.listMine(jwt.getSubject(), principalDomain.forScope(jwt));
    }

    @Operation(summary = "Serve MY stored, SANITIZED part SVG as a hardened image "
            + "(image/svg+xml + locked-down CSP). A part that is not mine is a 404. Owner = JWT subject.")
    @GetMapping("/{id}/svg")
    public Mono<ResponseEntity<String>> serveSvg(@AuthenticationPrincipal Jwt jwt,
                                                 @PathVariable String id) {
        String owner = jwt.getSubject();
        // Owner-scoped read: a part that is not the caller's yields empty → 404 (NOT 403),
        // so we never leak whether another user's part with this id exists.
        return service.getOwned(id, owner)
                .map(CharacterPartController::asHardenedSvg)
                .switchIfEmpty(Mono.error(ApiException.notFound("character part not found")));
    }

    /**
     * Wrap the stored SANITIZED svg in a response that serves it as an IMAGE with
     * hardened headers: {@code image/svg+xml}; a locked-down {@code Content-Security-
     * Policy}; {@code X-Content-Type-Options: nosniff} (no MIME-sniff to text/html); and
     * {@code Content-Disposition: inline} (served as an image, never as an inline-HTML
     * document). The body is already the sanitizer's safe subset.
     */
    private static ResponseEntity<String> asHardenedSvg(VnCharacterPart part) {
        return ResponseEntity.ok()
                .header("Content-Security-Policy", SVG_CSP)
                .header("X-Content-Type-Options", "nosniff")
                .header("Content-Disposition", "inline")
                .contentType(MediaType.valueOf("image/svg+xml"))
                .body(part.svg());
    }
}
