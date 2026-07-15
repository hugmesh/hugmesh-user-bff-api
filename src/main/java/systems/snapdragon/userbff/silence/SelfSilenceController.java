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
import systems.snapdragon.userbff.auth.AdminBffInternalClient;
import systems.snapdragon.userbff.security.PrincipalDomain;

import java.time.Instant;
import java.util.Locale;
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
 * of it) — login/home stays normal for the silenced user. The homeserver localparts
 * used for the two visibility-hide seams are resolved CLAIM-FIRST (the {@code
 * localpart}/{@code mastodon_localpart} claims {@code
 * BffSessionAuthenticationWebFilter.syntheticJwt} stamps from admin-bff's PERSISTED,
 * collision-checked {@code account.localpart}/{@code account.mastodon_localpart}),
 * else via a real internal account read — mirrors {@code MatrixProxyController
 * .resolveCanonicalLocalpart}/{@code MediaPoisonController.resolveAccountView} (this
 * org's established duplication pattern) — see {@link #localpart}. Never the raw JWT
 * {@code preferred_username}/{@code sub}, which two different accounts can share.
 */
@Tag(name = "Self-silence", description = "Self-service visibility hide (owner = JWT subject). NOT a ban: no role/suspension/revocation.")
@RestController
@RequestMapping("/bff/user")
@PreAuthorize("hasRole('USER')")
@Validated
public class SelfSilenceController {

    private final SelfSilenceService silence;
    private final PrincipalDomain principalDomain;
    private final AdminBffInternalClient adminBff;

    public SelfSilenceController(SelfSilenceService silence, PrincipalDomain principalDomain,
                                 AdminBffInternalClient adminBff) {
        this.silence = silence;
        this.principalDomain = principalDomain;
        this.adminBff = adminBff;
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
        String owner = jwt.getSubject();
        String domain = principalDomain.forScope(jwt);
        return Mono.zip(matrixLocalpart(jwt), mastodonLocalpart(jwt))
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
        return Mono.zip(matrixLocalpart(jwt), mastodonLocalpart(jwt))
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

    /** The caller's PERSISTED, collision-checked Matrix localpart — see {@link #localpart}. */
    private Mono<String> matrixLocalpart(Jwt jwt) {
        return localpart(jwt, "matrix");
    }

    /** The caller's PERSISTED, collision-checked Mastodon fold — see {@link #localpart}. */
    private Mono<String> mastodonLocalpart(Jwt jwt) {
        return localpart(jwt, "mastodon");
    }

    /**
     * The caller's homeserver localpart FOR {@code platform}, used only for the two
     * visibility-hide seams. CLAIM-FIRST (the {@code localpart}/{@code
     * mastodon_localpart} claim on the synthetic {@code bff_}-session Jwt — see the
     * class doc), else a real internal account read via {@link #resolveAccountView}
     * — mirrors {@code MediaPoisonController.localpart}'s claim-first + adminBff-
     * fallback shape (this org's established duplication pattern).
     *
     * <p>UNLIKE the homeserver-MINT call sites ({@code MatrixProxyController} et al.),
     * this NEVER fails closed: a self-silence hide is documented best-effort + gated
     * ({@link SelfSilenceService} class javadoc), so an unresolved identity degrades
     * to {@code ""} and {@code SelfSilenceService#hidePlatform}'s existing blank-check
     * just skips that leg rather than 401/409-ing the caller's own activate/cancel.
     */
    private Mono<String> localpart(Jwt jwt, String platform) {
        boolean mastodon = "mastodon".equalsIgnoreCase(platform);
        String claim = jwt.getClaimAsString(mastodon ? "mastodon_localpart" : "localpart");
        if (claim != null && !claim.isBlank()) {
            return Mono.just(claim);
        }
        return resolveAccountView(jwt)
                .map(a -> mastodon ? a.mastodonLocalpart() : a.localpart())
                .defaultIfEmpty("")
                .onErrorResume(e -> Mono.just(""));
    }

    /**
     * Resolve the account view for a real, externally-issued Casdoor JWT that carries
     * no synthetic-session localpart claim — the SAME {@code (provider, handle)} →
     * account-id derivation {@code MatrixProxyController.resolveCanonicalLocalpart}/
     * {@code MediaPoisonController.resolveAccountView} use. Best-effort: any lookup
     * failure (including "no registered account") completes EMPTY rather than
     * erroring, so {@link #localpart} degrades to {@code ""} instead of failing the
     * caller's own activate/cancel call.
     */
    private Mono<AdminBffInternalClient.AccountView> resolveAccountView(Jwt jwt) {
        String email = jwt.getClaimAsString("email");
        String pu = jwt.getClaimAsString("preferred_username");
        Mono<AdminBffInternalClient.AccountView> byEmail = (email != null && !email.isBlank())
                ? adminBff.getAccount(idFor("google", email)).onErrorResume(e -> Mono.empty())
                : Mono.empty();
        Mono<AdminBffInternalClient.AccountView> byUsername = (pu != null && !pu.isBlank())
                ? adminBff.getAccount(idFor("discord", pu)).onErrorResume(e -> Mono.empty())
                : Mono.empty();
        return byEmail.switchIfEmpty(byUsername);
    }

    /** Mirrors {@code AccountStore.idFor(provider, handle)} — the same textual identity-string
     *  convention {@code MatrixProxyController}/{@code MastodonProxyController} replicate. */
    private static String idFor(String provider, String handle) {
        return provider + ":" + handle.toLowerCase(Locale.ROOT);
    }
}
