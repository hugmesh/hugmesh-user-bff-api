package systems.snapdragon.userbff.client;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.constraints.Pattern;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.snapdragon.userbff.web.ValidationPatterns;

import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * CONNECTED APPS & DEVICES surface (owner-scoped, owner = JWT subject). Lists the
 * caller's native OAuth apps + device sessions on the homeservers (akkoma / Matrix)
 * and revokes one. The owner is ALWAYS the JWT subject — never a body/path field — so
 * a user can only ever see/revoke THEIR OWN clients.
 *
 * <ul>
 *   <li>GET    {@code /bff/user/connected-clients} — my connected apps + devices;</li>
 *   <li>DELETE {@code /bff/user/connected-clients/{id}} — revoke one of mine (writes the
 *       per-credential gateway revocation key, best-effort homeserver delete, audit
 *       stamp).</li>
 * </ul>
 *
 * <p>EXTERNAL-CLIENT-ROLE GATE (Part B): managing a personal client requires the
 * external-client role. The class-level {@code @PreAuthorize} requires the caller to
 * hold AT LEAST ONE external-client role ({@code ROLE_MATRIX_EXTERNAL_CLIENT} OR
 * {@code ROLE_MASTODON_EXTERNAL_CLIENT}) to reach this surface AT ALL (API leg) — this
 * is SEPARATE from the base {@code ROLE_MATRIX}/{@code ROLE_MASTODON} our-UI access. The
 * {@link ConnectedClientsService} additionally re-checks the SPECIFIC platform's
 * external-client role per client (service leg / defence-in-depth), so a caller with
 * only the matrix external-client role cannot revoke a mastodon client and vice-versa.
 * {@code ROLE_*_EXTERNAL_CLIENT} map automatically via the Casdoor authorities
 * converter — no converter change.
 */
@Tag(name = "Connected clients",
        description = "The caller's OWN connected apps + device sessions (owner = JWT subject). "
                + "Requires an external-client role.")
@RestController
@RequestMapping("/bff/user/connected-clients")
@PreAuthorize("hasRole('MATRIX_EXTERNAL_CLIENT') or hasRole('MASTODON_EXTERNAL_CLIENT')")
@Validated
public class ConnectedClientsController {

    private final ConnectedClientsService clients;

    public ConnectedClientsController(ConnectedClientsService clients) {
        this.clients = clients;
    }

    @Operation(summary = "List my connected apps + device sessions (owner = JWT subject). Requires an external-client role.")
    @GetMapping
    public Flux<ConnectedClient> mine(@AuthenticationPrincipal Jwt jwt) {
        String localpart = localpart(jwt);
        String bearer = homeserverBearer(jwt);
        return callerRoles().flatMapMany(roles ->
                clients.list(jwt.getSubject(), localpart, bearer, roles));
    }

    @Operation(summary = "Revoke one of my connected clients (per-credential gateway key + best-effort homeserver delete + audit stamp).")
    @DeleteMapping("/{id}")
    public Mono<ResponseEntity<Map<String, Object>>> revoke(
            @AuthenticationPrincipal Jwt jwt,
            @PathVariable @Pattern(regexp = ValidationPatterns.BLOCK_ID, message = "id must be a UUID") String id) {
        String localpart = localpart(jwt);
        String bearer = homeserverBearer(jwt);
        return callerRoles().flatMap(roles ->
                        clients.revoke(jwt.getSubject(), id, localpart, bearer, roles))
                .map(ResponseEntity::ok);
    }

    /**
     * The caller's homeserver localpart (handle) for the seam calls — Casdoor's
     * {@code preferred_username} claim; falls back to the subject. (Same derivation as
     * the self-silence surface.)
     */
    private static String localpart(Jwt jwt) {
        String pu = jwt.getClaimAsString("preferred_username");
        return (pu == null || pu.isBlank()) ? jwt.getSubject() : pu;
    }

    /**
     * The caller's homeserver bearer to forward to the (gated) homeserver client-API
     * read/revoke, if the gateway surfaced one as a JWT claim. Absent on the our-UI
     * Casdoor token (the homeserver leg is then a stub/best-effort and the gateway
     * revocation key is the real enforcement), so this is null-tolerant.
     */
    private static String homeserverBearer(Jwt jwt) {
        return jwt.getClaimAsString("hs_token");
    }

    /**
     * The caller's granted authority names from the reactive security context —
     * forwarded to the service so the external-client-role gate is re-checked there
     * (defence-in-depth). Defaults to the empty set if (unexpectedly) no authentication
     * is in context; the service then forbids any platform action.
     */
    private static Mono<Set<String>> callerRoles() {
        return ReactiveSecurityContextHolder.getContext()
                .map(ctx -> ctx.getAuthentication().getAuthorities().stream()
                        .map(a -> a.getAuthority())
                        .collect(Collectors.toUnmodifiableSet()))
                .defaultIfEmpty(Set.of());
    }
}
