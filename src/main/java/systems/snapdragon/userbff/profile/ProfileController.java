package systems.snapdragon.userbff.profile;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
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
public class ProfileController {

    private final ProfileService profiles;

    public ProfileController(ProfileService profiles) {
        this.profiles = profiles;
    }

    @Operation(summary = "Get my profile (owner = JWT subject).")
    @GetMapping
    public Mono<UserProfile> me(@AuthenticationPrincipal Jwt jwt) {
        return profiles.get(jwt.getSubject());
    }

    @Operation(summary = "Create/update my profile. The body's userId is ignored — the owner is the JWT subject.")
    @PutMapping
    public Mono<UserProfile> upsert(@AuthenticationPrincipal Jwt jwt, @RequestBody UserProfile body) {
        return profiles.save(jwt.getSubject(), body);
    }

    @Operation(summary = "Delete my profile.")
    @DeleteMapping
    public Mono<ResponseEntity<Void>> delete(@AuthenticationPrincipal Jwt jwt) {
        return profiles.delete(jwt.getSubject()).thenReturn(ResponseEntity.noContent().build());
    }

    @Operation(summary = "Change my Casdoor password (goes to the IdP, not the profile table).")
    @PostMapping("/password")
    public Mono<Map<String, Object>> changePassword(@AuthenticationPrincipal Jwt jwt,
                                                    @RequestBody Map<String, String> body) {
        return profiles.changePassword(jwt.getSubject(), body.get("oldPassword"), body.get("newPassword"))
                .thenReturn(ack("password-change", profiles.casdoorEnabled()));
    }

    @Operation(summary = "Change my Casdoor email (goes to the IdP, not the profile table).")
    @PostMapping("/email")
    public Mono<Map<String, Object>> changeEmail(@AuthenticationPrincipal Jwt jwt,
                                                 @RequestBody Map<String, String> body) {
        return profiles.changeEmail(jwt.getSubject(), body.get("email"))
                .thenReturn(ack("email-change", profiles.casdoorEnabled()));
    }

    /** Acknowledgement carrying whether the live Casdoor write ran or was stubbed. */
    private static Map<String, Object> ack(String op, boolean live) {
        return Map.of("op", op, "status", live ? "submitted" : "queued",
                "casdoor", live ? "live" : "stubbed");
    }
}
