package systems.hugmesh.userbff.character;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferLimitException;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.MediaType;
import org.springframework.http.codec.multipart.FilePart;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestPart;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.hugmesh.commons.web.ApiException;
import systems.hugmesh.userbff.media.ImageSniffer;
import systems.hugmesh.userbff.security.PrincipalDomain;

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
 *       moderated (a blocked sticker is a 422), uploaded, stored {@code status=PENDING},
 *       and queued for moderation. Returns the stored sticker;</li>
 *   <li>GET {@code /bff/user/character/stickers} — list MY stickers (newest first).</li>
 * </ul>
 *
 * <p>There is deliberately NO BFF serve endpoint for the sticker image: a sticker's
 * pixels live on the homeserver media repo (the {@code mxc://} the row carries) and are
 * fetched direct-to-homeserver by the Matrix client — NOT proxied through the BFF (the
 * avatar invariant). So this controller has no SVG-serve / hardened-CSP path (that is the
 * #82 user-DRAWN-SVG-part path, a different feature).
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
