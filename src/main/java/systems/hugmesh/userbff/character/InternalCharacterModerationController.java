package systems.hugmesh.userbff.character;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;
import systems.hugmesh.commons.web.ApiException;

/**
 * INTERNAL service-to-service moderation RECEIVER for the part/sticker ACTIVATION loop —
 * {@code POST /bff/user/internal/character/parts/{id}/moderation} and
 * {@code .../stickers/{id}/moderation}. The ONLY production flipper of a moderated row's
 * {@code status} from {@code PENDING} to {@code ACTIVE}/{@code REJECTED}; the hugmesh
 * admin-bff moderation reconciler (a LATER PR) calls it when a moderator resolves the
 * {@code @system} finding the row filed at save time.
 *
 * <p><b>SERVICE-PRINCIPAL ONLY — the whole security story.</b> This sits under the
 * {@code /bff/user/internal/**} prefix, which {@code SecurityConfig} gates to
 * {@code ROLE_SERVICE} EXCLUSIVELY (NOT ADMIN/MOD/USER/SUPERADMIN — the role hierarchy has
 * NO edge to SERVICE, so even SUPERADMIN is denied), and the
 * {@code @PreAuthorize("hasRole('SERVICE')")} here is the defence-in-depth method gate.
 * {@code ROLE_SERVICE} is the platform's service-account role (a Casdoor client-credentials
 * token carries it; no human login does), the SAME mechanism
 * {@link systems.hugmesh.userbff.notification.InternalNotificationController} and
 * snapdragon-federation-api use to gate their internal surfaces.
 *
 * <p>The target ROW {@code id} is a path variable and the resolved {@code status} comes
 * from the body — the service acts on behalf of the SYSTEM resolving a finding, NOT
 * owner==caller. That is precisely why it must be unreachable by any human JWT: a human
 * reaching this endpoint could ACTIVATE their own (or anyone's) PENDING content without
 * moderator review — a moderation bypass. The SERVICE gate is that boundary.
 *
 * <p>Behaviour (see {@link CharacterModerationService}): the flip is PENDING-guarded and
 * IDEMPOTENT — a second resolve, or a resolve of an already-{@code ACTIVE}/{@code
 * REJECTED}/unknown id, flips ZERO rows and is surfaced as a 404 (nothing-flipped, no-op);
 * a successful flip returns the post-flip row. An invalid {@code status} (not {@code
 * ACTIVE}/{@code REJECTED}) is a 400.
 *
 * <p>Purely ADDITIVE — the user-facing save/list/serve endpoints are unchanged.
 */
@Tag(name = "Character-moderation (internal receiver)", description = "SERVICE-PRINCIPAL "
        + "ONLY part/sticker status flip (PENDING→ACTIVE/REJECTED) when a moderator resolves "
        + "the finding. PENDING-guarded + idempotent (a no-op/unknown id is a 404).")
@RestController
@RequestMapping("/bff/user/internal/character")
@PreAuthorize("hasRole('SERVICE')")
@Validated
public class InternalCharacterModerationController {

    private final CharacterModerationService service;

    public InternalCharacterModerationController(CharacterModerationService service) {
        this.service = service;
    }

    /**
     * The resolve body. {@code status} is the RESOLVED moderation outcome — exactly
     * {@code ACTIVE} (the moderator cleared the finding / dismissed it) or {@code REJECTED}
     * (the moderator confirmed the content is bad / actioned it); a value outside that set
     * is a 400. {@code findingId} is the resolved federation finding id (audit context) and
     * {@code reviewer} the resolving moderator (audit context); neither is required for the
     * flip itself (the flip keys on the path {@code id}), and both are bounded.
     */
    public record ResolveRequest(
            @NotBlank @Pattern(regexp = "^(ACTIVE|REJECTED)$",
                    message = "status must be ACTIVE or REJECTED")
            String status,

            Long findingId,

            @Size(max = 255)
            String reviewer) {}

    @Operation(summary = "Flip a PENDING character PART to ACTIVE/REJECTED on finding "
            + "resolution (SERVICE-principal only; idempotent — an unknown/already-resolved "
            + "id is a 404).")
    @PostMapping("/parts/{id}/moderation")
    public Mono<VnCharacterPart> resolvePart(@PathVariable String id,
                                             @RequestBody @Valid ResolveRequest body) {
        return service.resolvePart(id, body.status(), body.findingId(), body.reviewer())
                .switchIfEmpty(Mono.error(ApiException.notFound(
                        "character part not found or not PENDING (no-op)")));
    }

    @Operation(summary = "Flip a PENDING expression STICKER to ACTIVE/REJECTED on finding "
            + "resolution (SERVICE-principal only; idempotent — an unknown/already-resolved "
            + "id is a 404).")
    @PostMapping("/stickers/{id}/moderation")
    public Mono<VnSticker> resolveSticker(@PathVariable String id,
                                          @RequestBody @Valid ResolveRequest body) {
        return service.resolveSticker(id, body.status(), body.findingId(), body.reviewer())
                .switchIfEmpty(Mono.error(ApiException.notFound(
                        "character sticker not found or not PENDING (no-op)")));
    }
}
