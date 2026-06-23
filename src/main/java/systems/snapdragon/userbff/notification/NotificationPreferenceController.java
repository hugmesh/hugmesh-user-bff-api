package systems.snapdragon.userbff.notification;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;
import systems.snapdragon.userbff.security.PrincipalDomain;

import java.util.Map;

/**
 * The per-category notification PREFERENCES endpoint — MIRRORS
 * {@link systems.snapdragon.userbff.prefstore.UserPreferencesController} exactly. The
 * owner is ALWAYS the JWT subject; a user can only ever read/write their OWN
 * preferences in their OWN brand. ROLE_USER floor + {@code @PreAuthorize}
 * defence-in-depth; domain-scoped (SUPERADMIN unscoped).
 *
 * <ul>
 *   <li>GET {@code /bff/user/notification-preferences} — the caller's resolved
 *       per-category preferences (every category at its default ENABLED, the user's
 *       explicit choices merged in). {@code account-restriction} is ALWAYS enabled
 *       (forced-on).</li>
 *   <li>PUT {@code /bff/user/notification-preferences} — upsert ONE category preference
 *       ({@code {"category":..., "enabled":...}}), returning the resolved view.
 *       {@code account-restriction} with {@code enabled=false} is COERCED to enabled
 *       (un-silenceable) — the durable row + the view always show it on.</li>
 * </ul>
 */
@Tag(name = "Notification preferences", description = "Per-category notification "
        + "preferences (owner = JWT subject, domain-scoped). account-restriction is "
        + "forced-on / un-silenceable.")
@RestController
@RequestMapping("/bff/user/notification-preferences")
@PreAuthorize("hasRole('USER')")
@Validated
public class NotificationPreferenceController {

    private final NotificationPreferenceService service;
    private final PrincipalDomain principalDomain;

    public NotificationPreferenceController(NotificationPreferenceService service,
                                            PrincipalDomain principalDomain) {
        this.service = service;
        this.principalDomain = principalDomain;
    }

    /** PUT body: upsert one category preference. {@code category} is a bounded
     *  alnum/hyphen token (the service rejects anything outside the known vocabulary);
     *  {@code enabled} is required so the toggle state is never ambiguous. */
    public record PreferenceUpsert(
            @NotBlank
            @Size(max = 64)
            @Pattern(regexp = "^[a-z][a-z-]{0,63}$",
                    message = "category must be a lower-alpha/hyphen token")
            String category,
            @jakarta.validation.constraints.NotNull
            Boolean enabled) {}

    @Operation(summary = "My notification preferences (defaults merged in; "
            + "account-restriction always enabled).")
    @GetMapping
    public Mono<Map<String, Boolean>> get(@AuthenticationPrincipal Jwt jwt) {
        return service.get(jwt.getSubject(), principalDomain.forScope(jwt));
    }

    @Operation(summary = "Upsert one notification-category preference (returns the "
            + "resolved view). account-restriction enabled=false is coerced to true.")
    @PutMapping
    public Mono<Map<String, Boolean>> put(@AuthenticationPrincipal Jwt jwt,
                                          @RequestBody
                                          @jakarta.validation.Valid PreferenceUpsert body) {
        return service.put(jwt.getSubject(), body.category(), body.enabled(),
                principalDomain.forScope(jwt));
    }
}
