package systems.snapdragon.userbff.client;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.constraints.Pattern;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.snapdragon.userbff.auth.AdminBffInternalClient;
import systems.snapdragon.userbff.hsproxy.ServiceTokenBroker;
import systems.snapdragon.userbff.security.PrincipalDomain;
import systems.snapdragon.userbff.web.ValidationPatterns;

import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
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

    private static final Logger log = LoggerFactory.getLogger(ConnectedClientsController.class);

    private final ConnectedClientsService clients;
    private final PrincipalDomain principalDomain;
    private final AdminBffInternalClient adminBff;

    /**
     * Constructs a {@code ConnectedClientsController} with its required collaborators.
     *
     * @param clients         the service that owns all connected-client persistence + revocation logic
     * @param principalDomain the helper that derives the brand-domain scope from the JWT issuer
     * @param adminBff        internal client used to resolve the caller's canonical, persisted
     *                        homeserver localpart for a real Casdoor JWT carrying no synthetic
     *                        {@code localpart} claim — see {@link #canonicalLocalpart}
     */
    public ConnectedClientsController(ConnectedClientsService clients, PrincipalDomain principalDomain,
                                      AdminBffInternalClient adminBff) {
        this.clients = clients;
        this.principalDomain = principalDomain;
        this.adminBff = adminBff;
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
        String bearer = homeserverBearer(jwt);
        String domain = principalDomain.forScope(jwt);
        // localpartFor is resolved PER PLATFORM (see localpartFor's javadoc for why matrix and
        // mastodon localparts must never share one resolution) and only actually invoked by the
        // service for a platform the caller holds the external-client role for AND that is
        // enabled — a resolution failure there is treated as "skip that platform's live merge"
        // (best-effort; the durable audit rows, keyed on jwt.getSubject() alone, are unaffected).
        return callerRoles().flatMapMany(roles ->
                clients.list(jwt.getSubject(), platform -> localpartFor(platform, jwt), bearer, domain, roles));
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
        @ApiResponse(responseCode = "409", description = "Caller's account has no persisted homeserver localpart yet (fail-closed localpart resolution)."),
        @ApiResponse(responseCode = "500", description = "Database error.")
    })
    @DeleteMapping("/{id}")
    public Mono<ResponseEntity<Map<String, Object>>> revoke(
            @AuthenticationPrincipal Jwt jwt,
            @PathVariable @Pattern(regexp = ValidationPatterns.BLOCK_ID, message = "id must be a UUID") String id) {
        String bearer = homeserverBearer(jwt);
        String domain = principalDomain.forScope(jwt);
        // UNLIKE mine() above: the localpart here keys the DURABLE per-credential gateway
        // revocation key (revocations.revokeConnectedClient), the actual enforcement
        // mechanism — writing it under an unresolved/wrong candidate would silently produce
        // a "revoked": true response that does NOT actually deny the credential. The service
        // resolves localpartFor for the SPECIFIC platform of the client being revoked (known
        // only after the audit-row lookup) and this leg fails CLOSED: a resolution error
        // propagates as a real error (401/409), never a fallback to an unchecked derivation.
        return callerRoles().flatMap(roles ->
                        clients.revoke(jwt.getSubject(), id, platform -> localpartFor(platform, jwt),
                                bearer, domain, roles))
                .map(ResponseEntity::ok);
    }

    // -------------------------------------------------------------------------
    // Internal helpers
    // -------------------------------------------------------------------------

    /**
     * Dispatches to the platform-specific canonical-localpart resolver. MUST NOT share one
     * resolution across platforms: {@link ServiceTokenBroker#mastodonLocalpart} folds
     * {@code [^a-z0-9_]} to {@code _}, so two DISTINCT valid Matrix localparts (e.g.
     * {@code john.doe} / {@code john-doe}) can collapse to the SAME raw Mastodon candidate —
     * exactly why admin-bff persists Mastodon's own, independently collision-checked
     * {@code mastodon_localpart} column (changeset 291). Using the Matrix-fold value for a
     * Mastodon gateway-revocation-key write (or vice versa) would target the wrong homeserver
     * identity — this dispatcher is what keeps {@link #mine} and {@link #revoke} correct for
     * BOTH platforms, unlike the single-platform {@code MatrixProxyController}/
     * {@code MastodonProxyController} this pattern originates from.
     */
    private Mono<String> localpartFor(String platform, Jwt jwt) {
        return "mastodon".equals(platform) ? mastodonLocalpart(jwt) : canonicalLocalpart(jwt);
    }

    /**
     * The caller's canonical MATRIX localpart for the seam calls (live homeserver read, and —
     * critically — the key of the durable per-credential gateway revocation entry written
     * by {@link #revoke}).
     *
     * <p>Byte-for-byte the same rationale as {@code MatrixProxyController#localpart}: prefers
     * the {@code localpart} claim {@code BffSessionAuthenticationWebFilter} threads onto the
     * synthetic Jwt from admin-bff's PERSISTED, collision-checked {@code account.localpart}
     * (native-login / {@code bff_}-session callers — the primary path). A REAL,
     * externally-issued Casdoor JWT presented directly to this route never passes through
     * that filter and so never carries the claim, but still reaches this method (this
     * route's {@code @PreAuthorize} accepts any validly-signed token holding an
     * external-client role) — the OLD behaviour here (deriving
     * {@code preferred_username}/{@code sub} independently) is exactly the
     * unchecked-candidate bug this fix closes: it can differ from the canonical, persisted
     * value another surface (or a previous native-login session) already registered for
     * this same account, so the gateway revocation key {@link #revoke} writes would target
     * the wrong identity — a "revoke connected client" call that silently doesn't revoke.
     *
     * @param jwt the caller's Casdoor JWT
     * @return a {@link Mono} of the canonical Matrix localpart; errors (never falls back to
     *         an unchecked derivation) when it cannot be established
     */
    private Mono<String> canonicalLocalpart(Jwt jwt) {
        String canonical = jwt.getClaimAsString("localpart");
        if (canonical != null && !canonical.isBlank()) {
            return Mono.just(canonical);
        }
        return resolveAccountView(jwt).flatMap(a -> {
            String lp = a.localpart();
            return (lp == null || lp.isBlank())
                    ? Mono.error(new ResponseStatusException(HttpStatus.CONFLICT,
                            "account has no persisted homeserver localpart yet "
                                    + "(fail-closed — will not re-derive an unchecked candidate)"))
                    : Mono.just(lp);
        });
    }

    /**
     * The caller's PERSISTED Mastodon localpart (admin-bff Liquibase changeset 291) — the
     * value the Mastodon homeserver account is keyed on. Byte-for-byte the same rationale as
     * {@code MastodonProxyController#mastodonLocalpart}: claim-first ({@code mastodon_localpart}
     * on the synthetic {@code bff_} session JWT), else a real internal account read
     * ({@link AdminBffInternalClient.AccountView#mastodonLocalpart()}), with a TRANSITIONAL
     * fallback (fold the canonical MATRIX localpart via {@link ServiceTokenBroker#mastodonLocalpart}
     * — exactly the pre-fix behaviour) only when neither the claim nor the account view carries
     * the Mastodon fold (an admin-bff that predates changeset 291), so a rollout where
     * user-bff leads admin-bff never breaks Mastodon. FAIL CLOSED (like the Matrix path) only
     * when even the Matrix localpart is unresolved.
     */
    private Mono<String> mastodonLocalpart(Jwt jwt) {
        String claim = jwt.getClaimAsString("mastodon_localpart");
        if (claim != null && !claim.isBlank()) {
            return Mono.just(claim);
        }
        return resolveAccountView(jwt).flatMap(a -> {
            String mastodon = a.mastodonLocalpart();
            if (mastodon != null && !mastodon.isBlank()) {
                return Mono.just(mastodon);
            }
            String matrix = a.localpart();
            return (matrix == null || matrix.isBlank())
                    ? Mono.error(new ResponseStatusException(HttpStatus.CONFLICT,
                            "account has no persisted homeserver localpart yet "
                                    + "(fail-closed — will not re-derive an unchecked candidate)"))
                    : Mono.just(ServiceTokenBroker.mastodonLocalpart(matrix));
        });
    }

    /**
     * Resolve the canonical {@link AdminBffInternalClient.AccountView} for a JWT that carries
     * no synthetic-session localpart claim. Byte-for-byte identical to
     * {@code MatrixProxyController}/{@code MastodonProxyController}'s copy (this org's
     * established duplication pattern for these small per-controller identity resolvers):
     * {@code email} claim -&gt; {@code google:<email-lc>}, else {@code preferred_username} -&gt;
     * {@code discord:<username-lc>}, FAIL CLOSED throughout.
     */
    private Mono<AdminBffInternalClient.AccountView> resolveAccountView(Jwt jwt) {
        String email = jwt.getClaimAsString("email");
        String pu = jwt.getClaimAsString("preferred_username");
        Mono<AdminBffInternalClient.AccountView> byEmail = (email != null && !email.isBlank())
                ? adminBff.getAccount(idFor("google", email))
                        .onErrorResume(WebClientResponseException.NotFound.class, e -> Mono.empty())
                : Mono.empty();
        Mono<AdminBffInternalClient.AccountView> byUsername = (pu != null && !pu.isBlank())
                ? adminBff.getAccount(idFor("discord", pu))
                        .onErrorResume(WebClientResponseException.NotFound.class, e -> Mono.empty())
                : Mono.empty();
        return byEmail.switchIfEmpty(byUsername)
                .switchIfEmpty(Mono.error(new ResponseStatusException(HttpStatus.UNAUTHORIZED,
                        "no registered account for this token's identity claims "
                                + "(fail-closed homeserver-localpart resolution)")));
    }

    /** Mirrors {@code AccountStore.idFor(provider, handle) = provider + ":" +
     *  handle.toLowerCase()} — the same textual convention {@code MatrixProxyController}
     *  and {@code MastodonProxyController} already replicate for this exact purpose. */
    private static String idFor(String provider, String handle) {
        return provider + ":" + handle.toLowerCase(Locale.ROOT);
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
