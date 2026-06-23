package systems.snapdragon.userbff.client;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.constraints.Pattern;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.snapdragon.userbff.security.PrincipalDomain;
import systems.snapdragon.userbff.web.ValidationPatterns;

import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * CONNECTED APPS &amp; DEVICES surface (owner-scoped, owner = JWT subject). Lists the
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
 *
 * <table>
 *   <caption>Caller-role access matrix</caption>
 *   <tr><th>Endpoint</th><th>Required role (API leg)</th><th>Service-leg re-check</th></tr>
 *   <tr><td>GET /connected-clients</td>
 *       <td>ROLE_MATRIX_EXTERNAL_CLIENT OR ROLE_MASTODON_EXTERNAL_CLIENT</td>
 *       <td>per-platform per-client</td></tr>
 *   <tr><td>DELETE /connected-clients/{id}</td>
 *       <td>ROLE_MATRIX_EXTERNAL_CLIENT OR ROLE_MASTODON_EXTERNAL_CLIENT</td>
 *       <td>specific platform's external-client role per client</td></tr>
 * </table>
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
    private final PrincipalDomain principalDomain;

    /**
     * Constructs a {@code ConnectedClientsController} with its required collaborators.
     *
     * @param clients         the service that owns all connected-client persistence + revocation logic
     * @param principalDomain the helper that derives the brand-domain scope from the JWT issuer
     */
    public ConnectedClientsController(ConnectedClientsService clients, PrincipalDomain principalDomain) {
        this.clients = clients;
        this.principalDomain = principalDomain;
    }

    // -------------------------------------------------------------------------
    // Read: list the caller's own connected apps and device sessions
    // -------------------------------------------------------------------------

    /**
     * Returns all connected clients (apps + device sessions) registered to the JWT subject.
     * The list merges durable audit rows with a best-effort live read from the homeserver;
     * the homeserver read is a GATED STUB-SEAM and may be skipped when not wired.
     *
     * @param jwt the already-validated Casdoor JWT (injected by Spring Security)
     * @return a {@link Flux} of the caller's {@link ConnectedClient} rows (may be empty)
     */
    @Operation(summary = "List my connected apps + device sessions (owner = JWT subject). Requires an external-client role.")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "The caller's connected apps + device sessions. Merges durable audit rows with live homeserver read (best-effort, may be empty when seams are stubbed)."),
        @ApiResponse(responseCode = "401", description = "Missing or invalid Casdoor JWT."),
        @ApiResponse(responseCode = "403", description = "Caller lacks ROLE_MATRIX_EXTERNAL_CLIENT or ROLE_MASTODON_EXTERNAL_CLIENT.")
    })
    @GetMapping
    public Flux<ConnectedClient> mine(@AuthenticationPrincipal Jwt jwt) {
        String localpart = localpart(jwt);
        String bearer = homeserverBearer(jwt);
        String domain = principalDomain.forScope(jwt);
        // Gather authority names and forward to the service for the per-client
        // platform-specific external-client role re-check (defence-in-depth).
        return callerRoles().flatMapMany(roles ->
                clients.list(jwt.getSubject(), localpart, bearer, domain, roles));
    }

    // -------------------------------------------------------------------------
    // Write: revoke one of the caller's own connected clients
    // -------------------------------------------------------------------------

    /**
     * Revokes one of the caller's connected clients. Revocation order:
     * (1) write the per-credential gateway revocation key so the gateway denies
     * future use within ≤5 s;
     * (2) best-effort DELETE at the homeserver (GATED STUB-SEAM);
     * (3) stamp {@code revoked_at} on the audit row.
     * All three steps are owner+domain scoped. Steps 2 and 3 are best-effort; the
     * gateway key is the durable enforcement.
     *
     * @param jwt the already-validated Casdoor JWT
     * @param id  the UUID of the connected-client audit row to revoke
     * @return a {@link Mono} wrapping a result map with keys {@code revocationKey}
     *         ({@code written} or {@code stubbed}) and {@code upstream}
     *         ({@code live} or {@code stubbed})
     */
    @Operation(
            summary = "Revoke one of my connected clients (per-credential gateway key + best-effort homeserver delete + audit stamp).",
            description = """
                    Revokes one of the caller's own connected clients by its audit-row id.
                    Revocation order: (1) write the per-credential gateway key
                    <code>hs:<platform>:<localpart>:<externalRef></code> (gateway denies future use within &#x2264;5s),
                    (2) best-effort DELETE at the homeserver, (3) stamp <code>revoked_at</code> on the audit row.
                    All three steps are owner+domain scoped. Steps 2 and 3 are best-effort; the gateway key is
                    the durable enforcement.
                    """)
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Client revoked. 'revocationKey' is 'written' or 'stubbed'; 'upstream' is 'live' or 'stubbed'."),
        @ApiResponse(responseCode = "400", description = "id is not a valid UUID."),
        @ApiResponse(responseCode = "401", description = "Missing or invalid Casdoor JWT."),
        @ApiResponse(responseCode = "403", description = "Caller lacks the external-client role for the client's platform (service leg re-check)."),
        @ApiResponse(responseCode = "404", description = "No such active connected client for this user."),
        @ApiResponse(responseCode = "500", description = "Database error.")
    })
    @DeleteMapping("/{id}")
    public Mono<ResponseEntity<Map<String, Object>>> revoke(
            @AuthenticationPrincipal Jwt jwt,
            @PathVariable @Pattern(regexp = ValidationPatterns.BLOCK_ID, message = "id must be a UUID") String id) {
        String localpart = localpart(jwt);
        String bearer = homeserverBearer(jwt);
        String domain = principalDomain.forScope(jwt);
        // Gather authority names and forward to the service for the per-platform
        // external-client role re-check (defence-in-depth, service leg).
        return callerRoles().flatMap(roles ->
                        clients.revoke(jwt.getSubject(), id, localpart, bearer, domain, roles))
                .map(ResponseEntity::ok);
    }

    // -------------------------------------------------------------------------
    // Internal helpers
    // -------------------------------------------------------------------------

    /**
     * The caller's homeserver localpart (handle) for the seam calls — Casdoor's
     * {@code preferred_username} claim; falls back to the subject. (Same derivation as
     * the self-silence surface.)
     *
     * @param jwt the caller's Casdoor JWT
     * @return the localpart string (never null)
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
     *
     * @param jwt the caller's Casdoor JWT
     * @return the homeserver bearer token, or {@code null} if not present
     */
    private static String homeserverBearer(Jwt jwt) {
        return jwt.getClaimAsString("hs_token");
    }

    /**
     * The caller's granted authority names from the reactive security context —
     * forwarded to the service so the external-client-role gate is re-checked there
     * (defence-in-depth). Defaults to the empty set if (unexpectedly) no authentication
     * is in context; the service then forbids any platform action.
     *
     * @return a {@link Mono} of an immutable set of authority strings (e.g.
     *         {@code ROLE_MATRIX_EXTERNAL_CLIENT})
     */
    private static Mono<Set<String>> callerRoles() {
        // Read the reactive security context rather than ThreadLocal — WebFlux
        // does not use a thread-bound context, so ReactiveSecurityContextHolder
        // is the only safe source for authorities mid-stream.
        return ReactiveSecurityContextHolder.getContext()
                .map(ctx -> ctx.getAuthentication().getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .collect(Collectors.toUnmodifiableSet()))
                .defaultIfEmpty(Set.of());
    }
}
