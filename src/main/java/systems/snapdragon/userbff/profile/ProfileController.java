package systems.snapdragon.userbff.profile;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

import java.util.Map;

/**
 * Owner-scoped profile endpoints. The owner is ALWAYS the JWT subject
 * ({@code jwt.getSubject()}) — never a path/body field — so a user can only ever
 * read/write their OWN profile. ROLE_USER floor (enforced by SecurityConfig path
 * rules) + {@code @PreAuthorize("hasRole('USER')")} defence-in-depth.
 *
 * <p>There is deliberately NO {@code /profile/{userId}} route: the only profile a
 * caller can address is their own, identified by the token.
 */
@Tag(name = "Profile", description = "The caller's OWN profile (owner = JWT subject). Password/email go to the Casdoor IdP.")
@RestController
@RequestMapping("/bff/user/profile")
@PreAuthorize("hasRole('USER')")
@Validated
public class ProfileController {

    private final ProfileService profiles;

    public ProfileController(ProfileService profiles) {
        this.profiles = profiles;
    }

    /** Change-password body (typed + validated; was an untyped Map). The IdP
     *  enforces the password policy; we only require non-blank fields here. */
    public record PasswordChangeRequest(
            String oldPassword,
            @NotBlank(message = "newPassword is required")
            @Size(min = 1, max = 256, message = "newPassword must be 1-256 chars") String newPassword) {}

    /** Change-email body (typed + validated; was an untyped Map). */
    public record EmailChangeRequest(
            @NotBlank(message = "email is required")
            @Email(message = "email must be a valid address")
            @Size(max = 320, message = "email must be at most 320 chars") String email) {}

    @Operation(summary = "Get my profile (owner = JWT subject).")
    @GetMapping
    public Mono<UserProfile> me(@AuthenticationPrincipal Jwt jwt) {
        return profiles.get(jwt.getSubject());
    }

    @Operation(summary = "Create/update my profile. The body's userId is ignored — the owner is the JWT subject; the vanity username is derived from the token.")
    @PutMapping
    public Mono<UserProfile> upsert(@AuthenticationPrincipal Jwt jwt, @Valid @RequestBody UserProfile body) {
        // owner = JWT SUBJECT (the row key); username = the vanity DNS label, derived
        // from the token (NOT the body) so the reserved-username guard can't be
        // bypassed by spoofing the body.
        return profiles.save(jwt.getSubject(), usernameOf(jwt), body);
    }

    /**
     * The caller's USERNAME for vanity purposes, derived from the JWT. Casdoor mints
     * the {@code preferred_username} claim = the user's login name (the DNS label
     * behind {@code <username>.snapdragon.systems}); we fall back to {@code name},
     * then to the subject only if neither claim is present. This is the documented
     * single home for "how the username is obtained from the token".
     */
    static String usernameOf(Jwt jwt) {
        String preferred = jwt.getClaimAsString("preferred_username");
        if (preferred != null && !preferred.isBlank()) {
            return preferred;
        }
        String name = jwt.getClaimAsString("name");
        if (name != null && !name.isBlank()) {
            return name;
        }
        return jwt.getSubject();
    }

    @Operation(summary = "Delete my profile.")
    @DeleteMapping
    public Mono<ResponseEntity<Void>> delete(@AuthenticationPrincipal Jwt jwt) {
        return profiles.delete(jwt.getSubject()).thenReturn(ResponseEntity.noContent().build());
    }

    @Operation(summary = "Change my Casdoor password (goes to the IdP, not the profile table).")
    @PostMapping("/password")
    public Mono<Map<String, Object>> changePassword(@AuthenticationPrincipal Jwt jwt,
                                                    @Valid @RequestBody PasswordChangeRequest body) {
        return profiles.changePassword(jwt.getSubject(), body.oldPassword(), body.newPassword())
                .thenReturn(ack("password-change", profiles.casdoorEnabled()));
    }

    @Operation(summary = "Change my Casdoor email (goes to the IdP, not the profile table).")
    @PostMapping("/email")
    public Mono<Map<String, Object>> changeEmail(@AuthenticationPrincipal Jwt jwt,
                                                 @Valid @RequestBody EmailChangeRequest body) {
        return profiles.changeEmail(jwt.getSubject(), body.email())
                .thenReturn(ack("email-change", profiles.casdoorEnabled()));
    }

    /** Acknowledgement carrying whether the live Casdoor write ran or was stubbed. */
    private static Map<String, Object> ack(String op, boolean live) {
        return Map.of("op", op, "status", live ? "submitted" : "queued",
                "casdoor", live ? "live" : "stubbed");
    }
}
