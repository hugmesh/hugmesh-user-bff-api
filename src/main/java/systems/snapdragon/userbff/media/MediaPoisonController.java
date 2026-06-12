package systems.snapdragon.userbff.media;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.MediaType;
import org.springframework.http.codec.multipart.FilePart;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;
import systems.snapdragon.userbff.security.PrincipalDomain;
import systems.snapdragon.userbff.web.ApiException;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The BFF MEDIA-PROXY: the server-owned poison-before-ingest seam the UIs route uploads
 * through instead of POSTing media DIRECTLY to the homeserver. By owning the upload, the
 * AI-cloak happens before any homeserver sees the bytes, owns every served size, and the
 * decision is recorded SERVER-SIDE (auditable, badge/repost source of truth) — none of
 * which the prior direct-to-homeserver path could do.
 *
 * <p>ROLE_USER floor + {@code @PreAuthorize} defence-in-depth; owner = JWT subject (never
 * a body/path field), enforced in the service.
 *
 * <ul>
 *   <li>POST {@code /bff/user/media/upload} — multipart (file + platform + mode +
 *       roomId/description). Poison-then-forward (or forward-through) proxy: returns the
 *       homeserver {@code media_id}/{@code mxc} EXACTLY as the homeserver would (so the UI
 *       compose logic is untouched) PLUS the server-owned decision (mode/status/backend);</li>
 *   <li>GET {@code /bff/user/media/capability} — the worker backend ({@code cuda|rocm|cpu|
 *       none}) + offered modes + ETA, so the composer renders an HONEST shield state up
 *       front (incl. {@code Unavailable} when the heavy tier is absent);</li>
 *   <li>GET {@code /bff/user/media/status/{ref}} — the caller's OWN decision for a media
 *       ref (badge polling), owner-scoped.</li>
 * </ul>
 */
@Tag(name = "Media-cloak", description = "Poison-before-ingest media proxy (owner = JWT subject). "
        + "Best-effort AI-cloak — 'AI-cloak applied', never 'protected' unless the round-trip survival gate passes.")
@RestController
@RequestMapping("/bff/user/media")
@PreAuthorize("hasRole('USER')")
@Validated
public class MediaPoisonController {

    private final MediaPoisonService service;
    private final MediaPoisoningProperties props;
    private final PrincipalDomain principalDomain;

    public MediaPoisonController(MediaPoisonService service, MediaPoisoningProperties props,
                                 PrincipalDomain principalDomain) {
        this.service = service;
        this.props = props;
        this.principalDomain = principalDomain;
    }

    @Operation(summary = "Upload media through the cloak proxy (poison-then-forward).",
            description = "Multipart: file (required) + platform (matrix|mastodon) + mode "
                    + "(glaze|nightshade|light|none, default from server) + roomId/description (passthrough). "
                    + "Returns the homeserver response verbatim + the server-owned cloak decision.")
    @PostMapping(value = "/upload", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public Mono<Map<String, Object>> upload(
            @AuthenticationPrincipal Jwt jwt,
            @RequestPart("file") FilePart file,
            @RequestPart(value = "platform") String platform,
            @RequestPart(value = "mode", required = false) String mode,
            @RequestPart(value = "roomId", required = false) String roomId,
            @RequestPart(value = "description", required = false) String description) {

        String owner = jwt.getSubject();
        String domain = principalDomain.forScope(jwt);
        String filename = file.filename();
        MediaType partType = file.headers().getContentType();
        String declaredType = partType == null ? null : partType.toString();

        return readBounded(file, props.getMaxUploadBytes())
                .flatMap(bytes -> service.upload(owner, platform, mode, bytes, filename, declaredType, domain))
                .map(outcome -> {
                    // Return the homeserver body EXACTLY as the homeserver would (UI compose
                    // logic untouched) + a server-owned cloak block the badge reads from.
                    Map<String, Object> body = new LinkedHashMap<>(outcome.homeserver());
                    var d = outcome.decision();
                    body.put("cloak", Map.of(
                            "status", d.status(),
                            "mode", d.mode(),
                            "backend", d.backend() == null ? "none" : d.backend(),
                            "mediaRef", d.mediaRef() == null ? "" : d.mediaRef()));
                    return body;
                });
    }

    @Operation(summary = "AI-cloak capability (worker backend + modes + ETA) for the shield state.")
    @GetMapping("/capability")
    public Mono<Map<String, Object>> capability(@AuthenticationPrincipal Jwt jwt) {
        return service.capability().map(h -> {
            Map<String, Object> out = new LinkedHashMap<>();
            String backend = h.backend() == null ? "none" : h.backend();
            out.put("backend", backend);
            out.put("available", !"none".equals(backend));
            out.put("modes", h.modes() == null ? java.util.List.of() : h.modes());
            out.put("etaSeconds", h.etaSeconds());
            out.put("defaultMode", props.getDefaultMode());
            out.put("fallbackMode", props.fallback().name().toLowerCase());
            out.put("featureEnabled", props.isEnabled());
            return out;
        });
    }

    @Operation(summary = "My cloak decision for a media ref (badge polling), owner-scoped.")
    @GetMapping("/status/{ref}")
    public Mono<MediaPoisonDecision> status(@AuthenticationPrincipal Jwt jwt,
                                            @PathVariable String ref) {
        return service.status(jwt.getSubject(), ref, principalDomain.forScope(jwt));
    }

    /**
     * Read a {@link FilePart} into a bounded byte array. The BFF holds the bytes in
     * memory (bounded) to cloak-then-forward; a part larger than the cap is rejected as a
     * clean 400 rather than buffered unbounded.
     */
    private static Mono<byte[]> readBounded(FilePart file, long maxBytes) {
        return DataBufferUtils.join(file.content(), (int) Math.min(maxBytes + 1, Integer.MAX_VALUE))
                .map(buf -> {
                    try {
                        byte[] out = new byte[buf.readableByteCount()];
                        buf.read(out);
                        return out;
                    } finally {
                        DataBufferUtils.release(buf);
                    }
                })
                .onErrorMap(DataBufferLimitMatch::isLimit,
                        e -> ApiException.badRequest("upload exceeds max size"))
                .flatMap(bytes -> bytes.length > maxBytes
                        ? Mono.error(ApiException.badRequest("upload exceeds max size"))
                        : Mono.just(bytes));
    }

    /** Tiny predicate helper: the join-limit overflow surfaces as a DataBufferLimitException. */
    private static final class DataBufferLimitMatch {
        static boolean isLimit(Throwable t) {
            return t instanceof org.springframework.core.io.buffer.DataBufferLimitException;
        }
    }
}
