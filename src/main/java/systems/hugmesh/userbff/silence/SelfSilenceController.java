package systems.hugmesh.userbff.silence;

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
import systems.hugmesh.userbff.auth.CanonicalIdentityResolver;
import systems.hugmesh.userbff.security.PrincipalDomain;

import java.time.Instant;
import java.util.Map;

/**
 * USER SELF-SILENCE surface (self-service visibility hide; NOT a ban). The owner is
 * ALWAYS the JWT subject -- never a body/path field -- so a user can only ever
 * silence/read/cancel THEMSELVES. ROLE_USER floor (the converter's
 * always-present floor) + {@code @PreAuthorize} defence-in-depth, exactly like
 * {@code BlockController}.
 *
 * <ul>
 *   <li>POST {@code /self-silence/activate} -- make myself invisible to others until
 *       {@code expiresAt} (future); I keep my session + full access.</li>
 *   <li>GET  {@code /self-silence/status} -- my current silence (active or cleared).</li>
 *   <li>POST {@code /self-silence/cancel} -- un-silence myself now (un-hide + clear).</li>
 *   <li>POST {@code /self-silence/email-mod} -- ask a mod/admin to reactivate me
 *       sooner (writes a self-silence-appeal moderation request; NOT SMTP).</li>
 * </ul>
 *
 * <p>INVARIANT: this surface never writes a Casdoor role, an {@code access_suspension}
 * row, or a revocation key (the {@link SelfSilenceService} is structurally incapable
 * of it) -- login/home stays normal for the silenced user. The homeserver localparts
 * used for the two visibility-hide seams are resolved by the shared {@link
 * CanonicalIdentityResolver} (claim-first from the {@code bff_}-session synthetic Jwt,
 * else the caller's OWN {@code casdoor:<subject>} account -- NEVER the raw JWT
 * {@code preferred_username}/{@code sub}, which two different accounts can share). UNLIKE
 * the homeserver-MINT sites this seam degrades to {@code ""} (best-effort hide) rather
 * than failing closed -- see the resolver's {@code *OrBlank} methods.
 */
@Tag(name = "Self-silence", description = "Self-service visibility hide (owner = JWT subject). NOT a ban: no role/suspension/revocation.")
@RestController
@RequestMapping("/bff/user")
@PreAuthorize("hasRole('USER')")
@Validated
public class SelfSilenceController {

    private final SelfSilenceService silence;
    private final PrincipalDomain principalDomain;
    private final CanonicalIdentityResolver identity;

    public SelfSilenceController(SelfSilenceService silence, PrincipalDomain principalDomain,
                                 CanonicalIdentityResolver identity) {
        this.silence = silence;
        this.principalDomain = principalDomain;
        this.identity = identity;
    }

    /**
     * Activate-self-silence body. {@code expiresAt} is REQUIRED and must be in the
     * FUTURE (a self-silence is always bounded -- the user auto-re-shows); a bad/past
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
        String owner = jwt.getSubject();
        String domain = principalDomain.forScope(jwt);
        return Mono.zip(identity.matrixLocalpartOrBlank(jwt), identity.mastodonLocalpartOrBlank(jwt))
                .flatMap(lp -> silence.activate(owner, lp.getT1(), lp.getT2(),
                        body.expiresAt(), body.reason(), domain));
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
        String owner = jwt.getSubject();
        String domain = principalDomain.forScope(jwt);
        return Mono.zip(identity.matrixLocalpartOrBlank(jwt), identity.mastodonLocalpartOrBlank(jwt))
                .flatMap(lp -> silence.cancel(owner, lp.getT1(), lp.getT2(), domain))
                .thenReturn(ResponseEntity.noContent().<Void>build());
    }

    @Operation(summary = "Email a mod/admin to reactivate me sooner (writes a self-silence-appeal request; NOT SMTP).")
    @PostMapping("/self-silence/email-mod")
    public Mono<Map<String, Object>> emailMod(@AuthenticationPrincipal Jwt jwt,
                                              @Valid @RequestBody EmailModRequest body) {
        return silence.requestEarlyReactivation(jwt.getSubject(), body.reason(),
                principalDomain.forScope(jwt));
    }
}
