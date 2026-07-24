package systems.hugmesh.userbff.notification;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;
import systems.hugmesh.userbff.notification.InternalNotificationDeliveryService.DeliveryResult;

/**
 * INTERNAL service-to-service deliver endpoint for the in-app notification FLOOR —
 * {@code POST /bff/user/internal/notifications}. The ONLY production writer of
 * {@code user_notifications}; the hugmesh-actions reconciler calls it.
 *
 * <p><b>SERVICE-PRINCIPAL ONLY — the whole security story.</b> This sits under the
 * {@code /bff/user/internal/**} prefix, which {@code SecurityConfig} gates to
 * {@code ROLE_SERVICE} EXCLUSIVELY (NOT ADMIN/MOD/USER/SUPERADMIN), and the
 * {@code @PreAuthorize("hasRole('SERVICE')")} here is the defence-in-depth method gate.
 * {@code ROLE_SERVICE} is the platform's service-account role (a Casdoor
 * client-credentials token carries it; no human login does), the SAME mechanism
 * snapdragon-federation-api uses to gate its internal username-availability oracle.
 *
 * <p>The target {@code (domain, userSubject)} comes from the REQUEST BODY (the service
 * acts on behalf of the SYSTEM for a named user — NOT owner==caller). That is precisely
 * why it must be unreachable by any human JWT: a human reaching this endpoint could
 * write a notification to ANY user — a notification-spoofing IDOR. The gate above is the
 * boundary that prevents it.
 *
 * <p>Behaviour (see {@link InternalNotificationDeliveryService}): honours the
 * per-category preference ({@code account-restriction} forced-on), and is idempotent —
 * the row id is the deterministic hash of the source event, so a retry is
 * INSERT-IF-ABSENT (a duplicate returns {@code delivered=true, deduped=true}, never a
 * second row). {@code title}/{@code body} are taken verbatim from the body (the
 * reconciler builds them); no actor identity is synthesised.
 *
 * <p>Purely ADDITIVE — the user-facing prefs/inbox endpoints are unchanged.
 */
@Tag(name = "Notifications (internal deliver)", description = "SERVICE-PRINCIPAL ONLY "
        + "in-app notification delivery (target taken from the body). Honours prefs "
        + "(account-restriction forced-on) and is idempotent on the source event.")
@RestController
@RequestMapping("/bff/user/internal/notifications")
@PreAuthorize("hasRole('SERVICE')")
@Validated
public class InternalNotificationController {

    private final InternalNotificationDeliveryService service;

    public InternalNotificationController(InternalNotificationDeliveryService service) {
        this.service = service;
    }

    /**
     * The deliver request. The TARGET {@code (domain, userSubject)} is supplied by the
     * service caller (the system delivers on the user's behalf). {@code category} is a
     * bounded lower-alpha/hyphen token (the service rejects anything outside the known
     * vocabulary). {@code sourceTable}+{@code sourceId} identify the source event and
     * drive the deterministic, retry-idempotent id. {@code body} is optional (a
     * title-only notification is valid).
     */
    public record DeliverRequest(
            @NotBlank @Size(max = 64)
            @Pattern(regexp = "^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$",
                    message = "domain must be a bounded token")
            String domain,

            @NotBlank @Size(max = 255)
            String userSubject,

            @NotBlank @Size(max = 64)
            @Pattern(regexp = "^[a-z][a-z-]{0,63}$",
                    message = "category must be a lower-alpha/hyphen token")
            String category,

            @NotBlank @Size(max = 512)
            String title,

            @Size(max = 100_000)
            String body,

            @NotBlank @Size(max = 128)
            @Pattern(regexp = "^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$",
                    message = "sourceTable must be a bounded token")
            String sourceTable,

            @NotBlank @Size(max = 255)
            String sourceId) {}

    @Operation(summary = "Deliver one in-app notification to the target user "
            + "(SERVICE-principal only; prefs honoured, account-restriction forced-on, "
            + "idempotent on the source event).")
    @PostMapping
    public Mono<DeliveryResult> deliver(@RequestBody @Valid DeliverRequest body) {
        return service.deliver(body.domain(), body.userSubject(), body.category(),
                body.title(), body.body(), body.sourceTable(), body.sourceId());
    }
}
