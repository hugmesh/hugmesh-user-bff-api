package net.hugmesh.userbff.reset;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import java.util.Map;

/**
 * ANONYMOUS password RESET — the flow a user who has FORGOTTEN their password can
 * actually reach.
 *
 * <p>Until this controller existed the platform had no such flow anywhere: the only
 * credential-write surface was {@code POST /bff/user/profile/password}, which is
 * {@code @PreAuthorize("hasRole('USER')")}, takes the owner from a live JWT, and requires
 * the CURRENT password — three preconditions a locked-out user cannot satisfy by
 * definition. Casdoor's own hosted reset page is unreachable on purpose (there is
 * deliberately no front-door route to Casdoor), and admin-bff has no reset endpoint
 * either. The net effect was that forgetting a password was PERMANENT.
 *
 * <h2>Why this lives beside {@code /bff/login} and not under {@code /bff/user/**}</h2>
 *
 * <p>{@code /bff/user/**} is the authenticated surface; putting a reset there would put it
 * behind the very session the user is trying to recover. This controller sits on the
 * pre-auth login surface that user-bff already owns ({@code /bff/login},
 * {@code /bff/register}, {@code /bff/session}) and is declared {@code permitAll} in
 * {@code SecurityConfig} by EXACT path — {@code /bff/password-reset/request} and
 * {@code /bff/password-reset/confirm}, never a {@code /**} subtree, following the
 * appeal-contact and theme precedents in the gateway's own public list.
 *
 * <h2>SHIPS DARK, and 503 rather than a polite lie</h2>
 *
 * <p>Both legs answer 503 while {@code casdoor.password-reset.enabled=false} (the
 * default), because the only two honest things to tell a locked-out visitor are "a code is
 * on its way" and "this mesh cannot do that" — and a stubbed 202 would be the first while
 * meaning the second. That is a deliberate divergence from the authenticated
 * change-password endpoint's {@code {"casdoor":"stubbed"}} acknowledgement, whose reader
 * is an authenticated user who can SEE the stub marker.
 *
 * <h2>Three layers open the SAME surface and all three must agree</h2>
 *
 * <p>Reaching these paths from a browser needs, beyond this controller:
 * <ul>
 *   <li>a gateway ROUTE — the two paths added to the user-bff predicate list in
 *       hugmesh-generator ({@code tests/stack/gateway-routes/fe/application-routes.yml}
 *       and {@code specs/cluster/apps/20-gateway-fe.yaml});</li>
 *   <li>a route-access PUBLIC row per exact path in
 *       {@code specs/cluster/manifests/route-access/initdb/20-schema.sql};</li>
 *   <li>the same two paths in hugmesh-gateway's {@code SecurityConfig.PUBLIC_PATHS}, whose
 *       coarse {@code anyExchange().authenticated()} floor 401s an anonymous caller BEFORE
 *       the route-access rule is ever consulted.</li>
 * </ul>
 * Miss any one and an anonymous reset 401s or 404s at the front door while every unit test
 * in this repo still passes — the front-page-parity invariant those files document.
 */
@Tag(name = "Password reset", description =
        "Anonymous forgot-password: request a mailed code, then redeem it. "
                + "Ships dark behind casdoor.password-reset.enabled.")
@RestController
@RequestMapping("/bff/password-reset")
@Validated
public class PasswordResetController {

    /**
     * Request body for leg 1. A USERNAME ONLY — deliberately not an email address: the
     * destination is whatever Casdoor already holds for the account, so this endpoint
     * cannot be used to mail a code to an attacker-chosen address, and it never has to
     * echo the real one back.
     */
    public record ResetRequest(
            @NotBlank(message = "username is required")
            @Size(max = 255, message = "username must be at most 255 chars") String username) {}

    /** Request body for leg 2 — the mailed code plus the replacement password. */
    public record ResetConfirm(
            @NotBlank(message = "username is required")
            @Size(max = 255, message = "username must be at most 255 chars") String username,
            @NotBlank(message = "code is required")
            @Size(max = 64, message = "code must be at most 64 chars") String code,
            @NotBlank(message = "newPassword is required")
            @Size(min = 1, max = 256, message = "newPassword must be 1-256 chars") String newPassword) {}

    private final PasswordResetService resets;

    public PasswordResetController(PasswordResetService resets) {
        this.resets = resets;
    }

    /**
     * Leg 1 — request a reset code. ALWAYS 202 with a FIXED body once the request is
     * well-formed, whether or not the username exists: a status or body that varied with
     * account existence would make this permitAll endpoint a membership oracle for the
     * whole mesh. 503 while the surface is dark (a fact about the service, not an account).
     */
    @Operation(summary = "Request a password-reset code, mailed by the IdP to the address it "
            + "holds for the account. ALWAYS 202 for a well-formed request — a non-existent "
            + "username is indistinguishable from an existing one (anti-enumeration). "
            + "503 when password reset is dark.")
    @PostMapping("/request")
    public Mono<ResponseEntity<Map<String, Object>>> request(@Valid @RequestBody ResetRequest body) {
        return resets.request(body.username())
                .thenReturn(ResponseEntity.accepted().body(Map.of(
                        "op", "password-reset-request",
                        // The SAME string for both outcomes. Any per-account variation
                        // here (even in wording) would reopen the oracle the service
                        // layer closes.
                        "status", "accepted")));
    }

    /**
     * Leg 2 — redeem the code and set the new password. 200 on a genuine IdP-confirmed
     * write; 400 on a refused one, with a single message that names both remaining causes
     * and distinguishes neither identity nor code; 503 while dark.
     */
    @Operation(summary = "Redeem a reset code and set a new password. 200 only when the IdP "
            + "actually wrote the credential; 400 with one non-revealing message when the code "
            + "or the new password was refused; 503 when password reset is dark.")
    @PostMapping("/confirm")
    public Mono<ResponseEntity<Map<String, Object>>> confirm(@Valid @RequestBody ResetConfirm body) {
        return resets.confirm(body.username(), body.code(), body.newPassword())
                .thenReturn(ResponseEntity.status(HttpStatus.OK).body(Map.of(
                        "op", "password-reset-confirm",
                        "status", "reset")));
    }
}
