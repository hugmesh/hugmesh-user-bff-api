package systems.hugmesh.userbff.session;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * Owner-scoped "active session management" endpoints — list / revoke the caller's OWN opaque
 * {@code bff_} login sessions. The owner is ALWAYS derived SERVER-SIDE from the validated JWT
 * principal ({@link SessionsService#accountIdFromJwt(Jwt)}); there is deliberately NO
 * {@code /sessions?account=} or {@code /sessions/{account}/...} route — a caller can only
 * ever address their OWN sessions, and even the revoke handle ({@code id}) is an opaque
 * fingerprint that only resolves against the caller's own live tokens. So a user can NEVER
 * see or revoke another user's sessions (cross-user isolation is structural, not a check).
 *
 * <p>ROLE_USER floor (the {@code /bff/user/**} SecurityConfig path rule) +
 * {@code @PreAuthorize("hasRole('USER')")} defence-in-depth — matching {@code ProfileController}.
 *
 * <p>admin-bff owns the {@code bff_session} table; every read/write here is delegated over
 * its internal API via {@link SessionsService} (user-bff has no session DB of its own).
 */
@Tag(name = "Sessions", description =
        "The caller's OWN active login sessions (owner = JWT-derived account). List + revoke.")
@RestController
@RequestMapping("/bff/user/sessions")
@PreAuthorize("hasRole('USER')")
public class SessionsController {

    private final SessionsService sessions;

    public SessionsController(SessionsService sessions) {
        this.sessions = sessions;
    }

    @Operation(summary = "List my active login sessions (owner = JWT-derived account; "
            + "ids are opaque fingerprints, never the raw session token).")
    @GetMapping
    public Flux<UserSession> listMine(@AuthenticationPrincipal Jwt jwt) {
        return sessions.listMine(jwt);
    }

    @Operation(summary = "Revoke one of my sessions by its opaque id. A foreign/unknown id is a "
            + "generic 404 (anti-enumeration). Revoking my own current session is allowed.")
    @DeleteMapping("/{id}")
    public Mono<ResponseEntity<Void>> revokeMine(@AuthenticationPrincipal Jwt jwt, @PathVariable String id) {
        return sessions.revokeMine(jwt, id).thenReturn(ResponseEntity.noContent().build());
    }
}
