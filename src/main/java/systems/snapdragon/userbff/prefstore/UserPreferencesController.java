package systems.snapdragon.userbff.prefstore;

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
import systems.snapdragon.userbff.web.ValidationPatterns;

import java.util.Map;

/**
 * The DURABLE per-user UI preferences endpoint. The compose surfaces (the
 * mastodon/matrix AI-poison toggle) and other UI-wave toggles read the resolved
 * preference view here and persist a change — so a toggle survives a reload/device
 * change instead of living only in the browser. The owner is ALWAYS the JWT subject;
 * a user can only ever read/write their OWN preferences in their OWN brand. ROLE_USER
 * floor + {@code @PreAuthorize} defence-in-depth; domain-scoped (SUPERADMIN unscoped).
 *
 * <ul>
 *   <li>GET {@code /bff/user/preferences} — the caller's resolved preferences (every
 *       stored value, server defaults merged in for any unset known preference, so
 *       the toggle state is always complete). Carries
 *       {@code media.poison.default} — the durable AI-poison default whose fallback
 *       MIRRORS the server {@code MediaPoisoningProperties.defaultMode}.</li>
 *   <li>PUT {@code /bff/user/preferences} — upsert ONE durable preference
 *       ({@code {"key":..., "value":...}}), returning the resolved view. The key +
 *       value are validated (the AI-poison default must be a valid cloak mode).</li>
 * </ul>
 *
 * <p>The read-only {@code GET /bff/user/media/capability} {@code defaultMode} (the
 * SERVER policy default) is untouched — this endpoint adds the per-USER durable
 * override on top of it.
 */
@Tag(name = "User preferences", description = "Durable per-user UI preferences "
        + "(owner = JWT subject, domain-scoped). Carries media.poison.default — the "
        + "per-user AI-poison default the compose toggle persists.")
@RestController
@RequestMapping("/bff/user/preferences")
@PreAuthorize("hasRole('USER')")
@Validated
public class UserPreferencesController {

    private final UserPreferencesService service;
    private final PrincipalDomain principalDomain;

    public UserPreferencesController(UserPreferencesService service, PrincipalDomain principalDomain) {
        this.service = service;
        this.principalDomain = principalDomain;
    }

    /** PUT body: upsert one durable preference (key + value), both bounded/validated. */
    public record PreferenceUpsert(
            @NotBlank
            @Size(max = 128)
            @Pattern(regexp = ValidationPatterns.PREF_STORE_KEY,
                    message = "key must be a dotted alnum/hyphen token")
            String key,
            @Size(max = 1024)
            String value) {}

    @Operation(summary = "My durable preferences (server defaults merged in for unset keys).")
    @GetMapping
    public Mono<Map<String, String>> get(@AuthenticationPrincipal Jwt jwt) {
        return service.get(jwt.getSubject(), principalDomain.forScope(jwt));
    }

    @Operation(summary = "Upsert one of my durable preferences (returns the resolved view).")
    @PutMapping
    public Mono<Map<String, String>> put(@AuthenticationPrincipal Jwt jwt,
                                         @org.springframework.web.bind.annotation.RequestBody
                                         @jakarta.validation.Valid PreferenceUpsert body) {
        return service.put(jwt.getSubject(), body.key(), body.value(), principalDomain.forScope(jwt));
    }
}
