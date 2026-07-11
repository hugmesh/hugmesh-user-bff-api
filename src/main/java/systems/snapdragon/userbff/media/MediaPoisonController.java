package systems.snapdragon.userbff.media;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.MediaType;
import org.springframework.http.codec.multipart.FilePart;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.http.HttpStatus;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Mono;
import systems.snapdragon.userbff.auth.AdminBffInternalClient;
import systems.snapdragon.userbff.hsproxy.ServiceTokenBroker;
import systems.snapdragon.userbff.security.PrincipalDomain;
import systems.snapdragon.commons.web.ApiException;

import java.util.LinkedHashMap;
import java.util.Locale;
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
    private final AdminBffInternalClient adminBff;

    public MediaPoisonController(MediaPoisonService service, MediaPoisoningProperties props,
                                 PrincipalDomain principalDomain, AdminBffInternalClient adminBff) {
        this.service = service;
        this.props = props;
        this.principalDomain = principalDomain;
        this.adminBff = adminBff;
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

        // Resolve the PERSISTED, collision-checked homeserver localpart for THIS platform (the
        // Matrix fold for matrix, the coarser Mastodon fold for mastodon) — MUST match what the
        // reverse-proxy controllers mint/load under so the media leg uploads to the SAME
        // homeserver account, never a second one, and can never collide onto a DIFFERENT
        // account's identity (the account-takeover-by-collision fix; see #localpart). Then read
        // the file (bounded), upload through the cloak service, and shape the response.
        return localpart(jwt, platform).flatMap(localpart ->
                readBounded(file, props.getMaxUploadBytes())
                        .flatMap(bytes -> service.upload(owner, localpart, platform, mode, bytes,
                                filename, declaredType, domain)))
                .map(MediaPoisonController::buildUploadResponse);
    }

    /** Merge the homeserver body with the server-owned cloak decision block for the UI badge. */
    private static Map<String, Object> buildUploadResponse(MediaPoisonService.UploadOutcome outcome) {
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
    }

    @Operation(summary = "AI-cloak capability (worker backend + modes + ETA) for the shield state.")
    @GetMapping("/capability")
    public Mono<Map<String, Object>> capability(@AuthenticationPrincipal Jwt jwt) {
        // Map the worker health response to the UI-facing capability document.
        return service.capability().map(this::buildCapabilityResponse);
    }

    /** Shape the worker health into the UI-facing capability document (backend/modes/ETA/policy). */
    private Map<String, Object> buildCapabilityResponse(PoisonModels.Health h) {
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

    /**
     * The caller's PERSISTED, collision-checked homeserver localpart FOR {@code platform} (admin-bff
     * Liquibase changesets 290/291) — the Matrix fold for {@code matrix}, the coarser Mastodon fold
     * for {@code mastodon}. Never a request field. Mirrors {@code MatrixProxyController.localpart} /
     * {@code MastodonProxyController.mastodonLocalpart}: claim-first (the {@code localpart} /
     * {@code mastodon_localpart} claim on the synthetic {@code bff_} session JWT), else a real
     * internal account read.
     *
     * <p>Using the persisted value — NOT the old {@code preferred_username}/{@code subject}
     * derivation — is REQUIRED, not cosmetic: that derivation folds differently from the canonical
     * one admin-bff uniqueness-checks (e.g. a {@code '+'} the Matrix fold STRIPS but the Mastodon
     * fold KEEPS as {@code '_'}), so two distinct accounts could produce the same media-leg
     * Mastodon localpart and the shared-service-password recover leg would let one take over the
     * other's homeserver identity through the media path — the exact takeover 290/291 close on the
     * proxy path, previously still open here.
     *
     * <p>TRANSITIONAL Mastodon fallback (admin-bff predating changeset 291): fold the persisted
     * Matrix localpart with {@link ServiceTokenBroker#mastodonLocalpart} — the pre-fix behaviour, so
     * a rollout where user-bff leads admin-bff never breaks the media leg. FAIL CLOSED when even the
     * Matrix localpart is unresolved.
     */
    private Mono<String> localpart(Jwt jwt, String platform) {
        boolean mastodon = "mastodon".equalsIgnoreCase(platform);
        String claim = jwt.getClaimAsString(mastodon ? "mastodon_localpart" : "localpart");
        if (claim != null && !claim.isBlank()) {
            return Mono.just(claim);
        }
        return resolveAccountView(jwt).flatMap(a -> {
            String canonical = mastodon ? a.mastodonLocalpart() : a.localpart();
            if (canonical != null && !canonical.isBlank()) {
                return Mono.just(canonical);
            }
            String matrix = a.localpart();
            if (matrix == null || matrix.isBlank()) {
                return Mono.error(new ResponseStatusException(HttpStatus.CONFLICT,
                        "account has no persisted homeserver localpart yet "
                                + "(fail-closed — will not re-derive an unchecked candidate)"));
            }
            return Mono.just(mastodon ? ServiceTokenBroker.mastodonLocalpart(matrix) : matrix);
        });
    }

    /**
     * Resolve the canonical {@link AdminBffInternalClient.AccountView} for a JWT with no
     * synthetic-session localpart claim — a REAL Casdoor JWT presented directly to this route
     * (still fully validated by {@code SecurityConfig}). Mirrors the two D6 proxy controllers'
     * resolution (this org's established duplication pattern), FAIL CLOSED on any lookup failure.
     */
    private Mono<AdminBffInternalClient.AccountView> resolveAccountView(Jwt jwt) {
        String email = jwt.getClaimAsString("email");
        String pu = jwt.getClaimAsString("preferred_username");
        Mono<AdminBffInternalClient.AccountView> byEmail = (email != null && !email.isBlank())
                ? adminBff.getAccount(idFor("google", email))
                        .onErrorResume(WebClientResponseException.NotFound.class, e -> Mono.empty())
                : Mono.empty();
        Mono<AdminBffInternalClient.AccountView> byUsername = (pu != null && !pu.isBlank())
                ? adminBff.getAccount(idFor("discord", pu))
                        .onErrorResume(WebClientResponseException.NotFound.class, e -> Mono.empty())
                : Mono.empty();
        return byEmail.switchIfEmpty(byUsername)
                .switchIfEmpty(Mono.error(new ResponseStatusException(HttpStatus.UNAUTHORIZED,
                        "no registered account for this token's identity claims "
                                + "(fail-closed homeserver-localpart resolution)")));
    }

    /** Mirrors {@code AccountStore.idFor(provider, handle)} — the same textual identity-string
     *  convention the two proxy controllers replicate rather than compile-depending on auth-core. */
    private static String idFor(String provider, String handle) {
        return provider + ":" + handle.toLowerCase(Locale.ROOT);
    }
}
