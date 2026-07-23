package systems.hugmesh.userbff.character;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferLimitException;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.CacheControl;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.codec.multipart.FilePart;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestPart;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.hugmesh.commons.web.ApiException;
import systems.hugmesh.userbff.media.ImageSniffer;
import systems.hugmesh.userbff.security.PrincipalDomain;

import java.time.Duration;
import java.util.regex.Pattern;

/**
 * Owner-scoped endpoints for VN-CHARACTER EXPRESSION STICKERS (Phase B1). A sticker is a
 * raster (PNG) snapshot the character rig renders at a canonical {@link StickerExpression}
 * — produced exactly like the avatar (an uploaded raster), so this MIRRORS the avatar
 * upload path: a multipart {@code file} part whose bytes must magic-byte-sniff to a real
 * raster image ({@link ImageSniffer}, which deliberately REJECTS SVG — the stored-XSS
 * gap), capped at {@value #MAX_STICKER_BYTES} bytes, then handed to
 * {@link StickerService} for MODERATE → UPLOAD → STORE-PENDING → FILE-MODERATION-FINDING.
 *
 * <p>The owner is ALWAYS the JWT subject ({@code jwt.getSubject()}) — never a path/body
 * field — so a user can only ever save/list their OWN stickers. ROLE_USER floor (enforced
 * by SecurityConfig path rules on {@code /bff/user/**}) +
 * {@code @PreAuthorize("hasRole('USER')")} defence-in-depth.
 *
 * <ul>
 *   <li>POST {@code /bff/user/character/stickers} — save a sticker: a multipart
 *       {@code file} (the rendered PNG) + {@code expression} (a canonical label). The
 *       bytes are sniffed (a non-raster / SVG is a 400), capped (oversize is a 400),
 *       moderated (a blocked sticker is a 422), uploaded, stored {@code status=PENDING}
 *       WITH the pixels (changelog 020), and queued for moderation. Returns the stored
 *       sticker;</li>
 *   <li>GET {@code /bff/user/character/stickers} — list MY stickers (newest first);</li>
 *   <li>GET {@code /bff/user/character/stickers/{slug}/body} — serve a sticker's stored
 *       pixels (the forum-ui sticker-token/picker/VN-sprite image source; slug = the row
 *       UUID id, which the list returns as {@code slug}). NOT owner-scoped on purpose —
 *       an {@code ACTIVE} sticker embedded in a post must render for every reader; the
 *       moderation/audience gates live in {@link StickerService#serveBody} (PENDING =
 *       owner-only preview, REJECTED never serves) and every miss is a uniform 404.</li>
 * </ul>
 *
 * <p>The Matrix side is unchanged: the pixels are ALSO uploaded to the homeserver media
 * repo (the {@code mxc://} the row carries, stub-gated) and the MSC2545 pack still
 * advertises {@code mxc://} refs fetched direct-to-homeserver by Matrix clients. The
 * BFF-stored body (020, mirroring the 016 SVG-part precedent) is the web-side serve
 * channel that makes sticker {@code <img>}s real for forum-ui.
 */
@Tag(name = "Character-stickers", description = "The caller's OWN VN-character expression "
        + "stickers (owner = JWT subject). Each is a rendered PNG, edge-AI moderated before "
        + "publish and reviewed by a moderator.")
@RestController
@RequestMapping("/bff/user/character/stickers")
@PreAuthorize("hasRole('USER')")
@Validated
public class StickerController {

    /** Maximum accepted sticker upload size — 1 MB (an MSC2545 sticker PNG is small;
     *  ~512KB is the practical ceiling, 1MB leaves headroom). Larger uploads are rejected
     *  with 400 before the bytes are read into memory in full. */
    private static final long MAX_STICKER_BYTES = 1L * 1024 * 1024;

    /** The serve-slug shape — the server mirror of forum-ui's {@code STICKER_SLUG_RE}
     *  ({@code stickers.ts}): 1..64 of {@code [a-z0-9_-]}. A DB-generated UUID id
     *  (lowercase hex + hyphens, 36 chars) always fits. */
    private static final Pattern SLUG_SHAPE = Pattern.compile("[a-z0-9_-]{1,64}");

    private final StickerService service;
    private final PrincipalDomain principalDomain;

    public StickerController(StickerService service, PrincipalDomain principalDomain) {
        this.service = service;
        this.principalDomain = principalDomain;
    }

    @Operation(summary = "Save a VN-character expression sticker (multipart 'file' = the rendered "
            + "PNG + 'expression' = a canonical label). The bytes are magic-byte-sniffed (a non-"
            + "raster/SVG is a 400), size-capped, edge-AI moderated (a blocked sticker is a 422), "
            + "uploaded to the homeserver media repo, stored status=PENDING, and queued for "
            + "moderation. Owner = JWT subject.")
    @PostMapping(consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public Mono<VnSticker> save(@AuthenticationPrincipal Jwt jwt,
                                @RequestPart("expression") String expression,
                                @RequestPart("file") FilePart file) {
        String owner = jwt.getSubject();
        String domain = principalDomain.forScope(jwt);
        String contentType = contentTypeOf(file);
        // Cheap first gate on the client header — a part not even CLAIMING to be an image
        // is a 400 before any bytes are read. The authoritative check is the magic-byte
        // sniff below (the header is attacker-controlled and is never trusted on its own).
        if (contentType == null || !contentType.toLowerCase().startsWith("image/")) {
            return Mono.error(ApiException.badRequest(
                    "character sticker must be an image (Content-Type image/*)"));
        }
        // Read the multipart bytes (enforcing the cap), then require the bytes to be a REAL
        // raster image by magic bytes (rejects SVG/HTML/polyglots labeled image/* — the
        // stored-XSS gap) and forward the SNIFFED type, never the client header. Only after
        // both gates pass is the service's MODERATE → UPLOAD → STORE leg run.
        return readCappedBytes(file)
                .flatMap(bytes -> storeSniffedSticker(owner, domain, expression, bytes));
    }

    @Operation(summary = "List MY VN-character expression stickers (newest first). Owner = JWT subject.")
    @GetMapping
    public Flux<VnSticker> listMine(@AuthenticationPrincipal Jwt jwt) {
        return service.listMine(jwt.getSubject(), principalDomain.forScope(jwt));
    }

    @Operation(summary = "Serve a sticker's stored image bytes by slug (= the sticker id the "
            + "list returns). ACTIVE stickers serve to any user in the sticker's domain (they "
            + "render inside other users' forum posts); a PENDING sticker serves ONLY to its "
            + "owner (composer preview); a REJECTED sticker never serves. Any miss — unknown/"
            + "malformed slug, foreign PENDING, REJECTED, no stored pixels — is a uniform 404.")
    @GetMapping("/{slug}/body")
    public Mono<ResponseEntity<byte[]>> serveBody(@AuthenticationPrincipal Jwt jwt,
                                                  @PathVariable String slug) {
        // Charset gate FIRST (the server mirror of forum-ui's STICKER_SLUG_RE): a slug
        // that cannot possibly be a row id is the same uniform 404 as an unknown one —
        // no separate 400 that would leak which misses were well-formed.
        if (slug == null || !SLUG_SHAPE.matcher(slug).matches()) {
            return Mono.error(ApiException.notFound("sticker not found"));
        }
        return service.serveBody(slug, jwt.getSubject(), principalDomain.forScope(jwt))
                .map(StickerController::asImageResponse)
                .switchIfEmpty(Mono.error(ApiException.notFound("sticker not found")));
    }

    /**
     * Wrap the stored pixels in an image response with hardened headers: the SNIFFED
     * MIME type recorded at save (never a client-declared one; {@code image/png} floor
     * for a legacy row with no recorded type), {@code nosniff}, and a locked-down CSP —
     * the same defensive posture as the SVG-part serve, cheap insurance even though the
     * bytes were magic-byte-verified raster at upload. Cacheable privately for 5 minutes:
     * a sticker row's pixels are immutable per id, but its moderation status is not, so
     * the TTL bounds how long a just-rejected sticker can keep rendering from cache.
     */
    private static ResponseEntity<byte[]> asImageResponse(StickerService.StickerBody body) {
        String type = body.contentType() == null || body.contentType().isBlank()
                ? MediaType.IMAGE_PNG_VALUE : body.contentType();
        return ResponseEntity.ok()
                .contentType(MediaType.parseMediaType(type))
                .header("X-Content-Type-Options", "nosniff")
                .header("Content-Security-Policy", "default-src 'none'")
                .cacheControl(CacheControl.maxAge(Duration.ofMinutes(5)).cachePrivate())
                .body(body.bytes());
    }

    /**
     * Magic-byte gate + delegate. The client {@code Content-Type} is NOT trusted: the
     * bytes must sniff to a known raster image ({@link ImageSniffer}, which deliberately
     * rejects SVG), else a 400 with NO moderation/upload attempted. The SNIFFED type is
     * the forwarded Content-Type.
     */
    private Mono<VnSticker> storeSniffedSticker(String owner, String domain, String expression,
                                                byte[] bytes) {
        String sniffed = ImageSniffer.detect(bytes);
        if (sniffed == null) {
            return Mono.error(ApiException.badRequest(
                    "character sticker must be a real image (magic-byte check failed)"));
        }
        return service.save(owner, domain, expression, bytes, sniffed);
    }

    /** The declared Content-Type of the uploaded part, or null when absent. */
    private static String contentTypeOf(FilePart file) {
        MediaType type = file.headers().getContentType();
        return type == null ? null : type.toString();
    }

    /**
     * Read the multipart file's content into a {@code byte[]}, rejecting (400) any upload
     * larger than {@link #MAX_STICKER_BYTES}. The cap is enforced AT the join (bounded by
     * {@code MAX_STICKER_BYTES + 1}) so an oversize part overflows the join as a
     * {@link DataBufferLimitException} — mapped to a clean 400 — instead of being buffered
     * unbounded or surfacing as a 500. Mirrors {@code ProfileController.readCappedBytes}.
     */
    private static Mono<byte[]> readCappedBytes(FilePart file) {
        return DataBufferUtils.join(file.content(),
                        (int) Math.min(MAX_STICKER_BYTES + 1, Integer.MAX_VALUE))
                .flatMap(StickerController::toCappedByteArray)
                .onErrorMap(StickerController::isJoinLimit, StickerController::oversizeBadRequest);
    }

    /** Convert a joined {@link DataBuffer} to a capped {@code byte[]}, releasing the
     *  buffer; fail with 400 when it exceeds the cap. */
    private static Mono<byte[]> toCappedByteArray(DataBuffer joined) {
        int size = joined.readableByteCount();
        if (size > MAX_STICKER_BYTES) {
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

    /** The canonical oversize-sticker 400 (size cap exceeded). */
    private static ApiException oversizeBadRequest(Throwable ignored) {
        return ApiException.badRequest(
                "character sticker exceeds the " + (MAX_STICKER_BYTES / (1024 * 1024)) + "MB limit");
    }
}
