package systems.snapdragon.userbff.silence;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Future;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;
import systems.snapdragon.userbff.security.PrincipalDomain;

import java.time.Instant;
import java.util.Map;

/**
 * USER SELF-SILENCE surface (self-service visibility hide; NOT a ban). The owner is
 * ALWAYS the JWT subject — never a body/path field — so a user can only ever
 * silence/read/cancel THEMSELVES. ROLE_USER floor (the converter's
 * always-present floor) + {@code @PreAuthorize} defence-in-depth, exactly like
 * {@code BlockController}.
 *
 * <ul>
 *   <li>POST {@code /self-silence/activate} — make myself invisible to others until
 *       {@code expiresAt} (future); I keep my session + full access.</li>
 *   <li>GET  {@code /self-silence/status} — my current silence (active or cleared).</li>
 *   <li>POST {@code /self-silence/cancel} — un-silence myself now (un-hide + clear).</li>
 *   <li>POST {@code /self-silence/email-mod} — ask a mod/admin to reactivate me
 *       sooner (writes a self-silence-appeal moderation request; NOT SMTP).</li>
 * </ul>
 *
 * <p>INVARIANT: this surface never writes a Casdoor role, an {@code access_suspension}
 * row, or a revocation key (the {@link SelfSilenceService} is structurally incapable
 * of it) — login/home stays normal for the silenced user. The homeserver
 * localpart used for the visibility-hide seams comes from the JWT
 * {@code preferred_username} claim.
 */
@Tag(name = "Self-silence", description = "Self-service visibility hide (owner = JWT subject). NOT a ban: no role/suspension/revocation.")
@RestController
@RequestMapping("/bff/user")
@PreAuthorize("hasRole('USER')")
@Validated
public class SelfSilenceController {

    private final SelfSilenceService silence;
    private final PrincipalDomain principalDomain;

    public SelfSilenceController(SelfSilenceService silence, PrincipalDomain principalDomain) {
        this.silence = silence;
        this.principalDomain = principalDomain;
    }

    /**
     * Activate-self-silence body. {@code expiresAt} is REQUIRED and must be in the
     * FUTURE (a self-silence is always bounded — the user auto-re-shows); a bad/past
     * value is a clean 400 before the service. {@code reason} is optional free text.
     */
    public record ActivateRequest(
            @NotNull(message = "expiresAt is required")
            @Future(message = "expiresAt must be in the future") Instant expiresAt,
            @Size(max = 2048, message = "reason must be at most 2048 chars") String reason) {}

    /** Email-mod (early-reactivate) body. {@code reason} is the optional note. */
    public record EmailModRequest(
            @Size(max = 2048, message = "reason must be at most 2048 chars") String reason) {}

    @Operation(summary = "Activate my self-silence (hide me from others until expiresAt). I keep my own access.")
    @PostMapping("/self-silence/activate")
    public Mono<SelfSilence> activate(@AuthenticationPrincipal Jwt jwt,
                                      @Valid @RequestBody ActivateRequest body) {
        return silence.activate(jwt.getSubject(), localpart(jwt), body.expiresAt(), body.reason(),
                principalDomain.forScope(jwt));
    }

    @Operation(summary = "My self-silence status (active or cleared).")
    @GetMapping("/self-silence/status")
    public Mono<ResponseEntity<SelfSilence>> status(@AuthenticationPrincipal Jwt jwt) {
        return silence.status(jwt.getSubject(), principalDomain.forScope(jwt))
                .map(ResponseEntity::ok)
                .defaultIfEmpty(ResponseEntity.noContent().build());
    }

    @Operation(summary = "Cancel my self-silence now (un-hide + clear).")
    @PostMapping("/self-silence/cancel")
    public Mono<ResponseEntity<Void>> cancel(@AuthenticationPrincipal Jwt jwt) {
        return silence.cancel(jwt.getSubject(), localpart(jwt), principalDomain.forScope(jwt))
                .thenReturn(ResponseEntity.noContent().<Void>build());
    }

    @Operation(summary = "Email a mod/admin to reactivate me sooner (writes a self-silence-appeal request; NOT SMTP).")
    @PostMapping("/self-silence/email-mod")
    public Mono<Map<String, Object>> emailMod(@AuthenticationPrincipal Jwt jwt,
                                              @Valid @RequestBody EmailModRequest body) {
        return silence.requestEarlyReactivation(jwt.getSubject(), body.reason(),
                principalDomain.forScope(jwt));
    }

    /**
     * The caller's homeserver localpart (handle) for the visibility-hide seams —
     * Casdoor's {@code preferred_username} claim. Falls back to the subject if the
     * claim is absent; the homeserver seams are best-effort + gated anyway.
     */
    private static String localpart(Jwt jwt) {
        String pu = jwt.getClaimAsString("preferred_username");
        return (pu == null || pu.isBlank()) ? jwt.getSubject() : pu;
    }
}
