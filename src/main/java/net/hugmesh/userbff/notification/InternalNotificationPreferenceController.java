package net.hugmesh.userbff.notification;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import java.util.Map;

/**
 * INTERNAL, READ-ONLY service-to-service lookup of one owner's effective notification
 * preferences: {@code GET /bff/user/internal/notification-preferences/{owner}?domain=...}.
 * It exists so admin-bff's external-channel reconciler (Matrix DM / Akkoma / phpBB / email)
 * can consult the user's per-category choices before sending. Until now the only reads were
 * the owner-facing {@code /bff/user/notification-preferences} (JWT subject = owner) and the
 * in-process lookup inside {@link InternalNotificationDeliveryService}.
 *
 * <p><b>SERVICE-PRINCIPAL ONLY.</b> Same gate as {@link InternalNotificationController}: the
 * {@code /bff/user/internal/**} prefix is {@code ROLE_SERVICE} exclusively in
 * {@code SecurityConfig}, and the {@code @PreAuthorize} here is the method-level backstop.
 * The owner is named in the PATH (the caller reads on behalf of the system, owner != caller),
 * which is why no human JWT may reach it.
 *
 * <p><b>Domain-scoped, never cross-domain.</b> {@code domain} is a REQUIRED query parameter
 * and is always passed to the service as a concrete value. The service treats a {@code null}
 * domain as the SUPERADMIN cross-domain bypass, so an absent or blank value is a 400 here
 * rather than a silent unscoped read.
 *
 * <p>The body is the same defaults-merged map {@link NotificationPreferenceService#get}
 * returns to the owner: every known category, enabled unless the owner stored a choice, with
 * {@code account-restriction} reported enabled regardless of any stored row. An owner with
 * no rows reads as all-enabled, so an unknown owner is a 200, not a 404.
 */
@Tag(name = "Notification preferences (internal read)", description = "SERVICE-PRINCIPAL ONLY "
        + "read of an owner's effective per-category notification preferences (domain-scoped; "
        + "account-restriction always enabled).")
@RestController
@RequestMapping("/bff/user/internal/notification-preferences")
@PreAuthorize("hasRole('SERVICE')")
@Validated
public class InternalNotificationPreferenceController {

    private final NotificationPreferenceService service;

    public InternalNotificationPreferenceController(NotificationPreferenceService service) {
        this.service = service;
    }

    @Operation(summary = "Effective per-category notification preferences of one owner in one "
            + "domain (SERVICE-principal only; defaults merged in, account-restriction always "
            + "enabled, unknown owner reads as all-enabled).")
    @GetMapping("/{owner}")
    public Mono<Map<String, Boolean>> read(
            @PathVariable @NotBlank @Size(max = 255) String owner,
            @RequestParam @NotBlank @Size(max = 64)
            @Pattern(regexp = "^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$",
                    message = "domain must be a bounded token")
            String domain) {
        return service.get(owner, domain);
    }
}
