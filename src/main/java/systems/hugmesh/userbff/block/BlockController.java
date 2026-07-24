package systems.hugmesh.userbff.block;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
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
import systems.hugmesh.userbff.security.PrincipalDomain;
import systems.hugmesh.userbff.web.ValidationPatterns;

import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Owner-scoped self-blocking + instance-block recommendation. The owner is ALWAYS
 * the JWT subject — never a body/path field — so a user can only ever
 * read/create/delete their OWN blocks. ROLE_USER floor + {@code @PreAuthorize}
 * defence-in-depth.
 *
 * <ul>
 *   <li>GET/DELETE {@code /blocks} — the caller's own self-blocks (durable row);
 *       owner-scoped, ROLE_USER floor (a platform-only principal can still manage
 *       blocks they already own, so these use {@code hasAnyRole}).</li>
 *   <li>POST {@code /blocks} — create a self-block (durable row + best-effort
 *       external Matrix/Mastodon push, STUBBED by default). PLATFORM-ROLE GATED:
 *       a {@code matrix} block requires {@code ROLE_MATRIX}, a {@code mastodon}
 *       block requires {@code ROLE_MASTODON} (an {@code internal} block needs only
 *       the ROLE_USER floor) — a principal that does not hold the platform's access
 *       role cannot push an external mute to a homeserver it has no access to.</li>
 *   <li>POST {@code /recommend-instance-block} — starts the USER->MOD->ADMIN
 *       instance-block chain via federation-api (a recommendation, not a block).
 *       Requires a homeserver platform role ({@code ROLE_MATRIX} OR
 *       {@code ROLE_MASTODON}) — only a platform participant recommends an instance
 *       block.</li>
 * </ul>
 *
 * <p>Request bodies are typed + {@code @Valid}-ated records (was an untyped
 * {@code Map}) so a missing {@code target}/{@code instance} or a bad
 * {@code platform} is a clean 400 with a field error BEFORE the service / DB CHECK
 * (005 {@code ck_user_block_platform}); the service still re-checks as
 * defence-in-depth.
 *
 * <p>DEFENCE-IN-DEPTH for the platform-role gate: the method-level
 * {@code @PreAuthorize} (SpEL on the request-body {@code platform}) is the API leg;
 * {@link BlockService} re-checks the SAME platform role against the caller's
 * authorities (service leg) so the rule holds even if a caller reaches the service
 * by another path. {@code ROLE_MATRIX}/{@code ROLE_MASTODON} map automatically via
 * the Casdoor authorities converter — no converter change.
 *
 * <table>
 *   <caption>Caller-role access matrix</caption>
 *   <tr><th>Endpoint</th><th>Required role</th></tr>
 *   <tr><td>GET /blocks</td><td>ROLE_USER (floor)</td></tr>
 *   <tr><td>POST /blocks (internal)</td><td>ROLE_USER (floor)</td></tr>
 *   <tr><td>POST /blocks (matrix)</td><td>ROLE_USER + ROLE_MATRIX</td></tr>
 *   <tr><td>POST /blocks (mastodon)</td><td>ROLE_USER + ROLE_MASTODON</td></tr>
 *   <tr><td>DELETE /blocks/{id}</td><td>ROLE_USER (floor)</td></tr>
 *   <tr><td>POST /recommend-instance-block</td><td>ROLE_MATRIX or ROLE_MASTODON</td></tr>
 * </table>
 */
@Tag(name = "Self-block", description = "The caller's OWN blocks (owner = JWT subject) + instance-block recommendation.")
@RestController
@RequestMapping("/bff/user")
@PreAuthorize("hasRole('USER')")
@Validated
public class BlockController {

    private final BlockService blocks;
    private final PrincipalDomain principalDomain;

    /**
     * Constructs a {@code BlockController} with its required collaborators.
     *
     * @param blocks          the service that owns all block persistence + external push logic
     * @param principalDomain the helper that derives the brand-domain scope from the JWT issuer
     */
    public BlockController(BlockService blocks, PrincipalDomain principalDomain) {
        this.blocks = blocks;
        this.principalDomain = principalDomain;
    }

    // -------------------------------------------------------------------------
    // Request body records
    // -------------------------------------------------------------------------

    /**
     * Create-self-block body. {@code target} (the blocked identity) is required;
     * {@code platform} is optional (defaults to {@code internal} in the service)
     * but, when supplied, must be one of the {@code user_block.platform} vocabulary
     * — mirrors the 005 CHECK + {@code UserBlock.validPlatform}.
     *
     * @param target   the identity being blocked (handle, MXID, Fediverse address, etc.)
     * @param platform the homeserver platform ({@code matrix}, {@code mastodon}, or
     *                 {@code internal}); defaults to {@code internal} when omitted
     */
    public record BlockRequest(
            @NotBlank(message = "target is required")
            @Size(max = 512, message = "target must be at most 512 chars") String target,
            @Pattern(regexp = ValidationPatterns.PLATFORM,
                    message = "platform must be matrix|mastodon|internal") String platform) {}

    /**
     * Recommend-instance-block body. {@code instance} (the homeserver/domain) is
     * required; {@code reason} is free text.
     *
     * @param instance the homeserver domain to recommend blocking (e.g. {@code bad.example.com})
     * @param reason   optional moderator-facing explanation (max 2048 chars)
     */
    public record RecommendRequest(
            @NotBlank(message = "instance is required")
            @Size(max = 512, message = "instance must be at most 512 chars") String instance,
            @Size(max = 2048, message = "reason must be at most 2048 chars") String reason) {}

    // -------------------------------------------------------------------------
    // Read: list the caller's own blocks
    // -------------------------------------------------------------------------

    /**
     * Returns all durable self-block rows owned by the JWT subject.
     *
     * @param jwt the already-validated Casdoor JWT (injected by Spring Security)
     * @return a {@link Flux} of the caller's {@link UserBlock} rows (may be empty)
     */
    @Operation(summary = "List my self-blocks.")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "The caller's own self-blocks (may be empty)."),
        @ApiResponse(responseCode = "401", description = "Missing or invalid Casdoor JWT."),
        @ApiResponse(responseCode = "403", description = "Principal lacks ROLE_USER.")
    })
    @GetMapping("/blocks")
    public Flux<UserBlock> mine(@AuthenticationPrincipal Jwt jwt) {
        return blocks.list(jwt.getSubject(), principalDomain.forScope(jwt));
    }

    // -------------------------------------------------------------------------
    // Write: create a self-block (durable + best-effort external push)
    // -------------------------------------------------------------------------

    /**
     * Create a self-block. PLATFORM-ROLE GATED at the method level (API leg): a
     * {@code matrix} target needs {@code ROLE_MATRIX}, a {@code mastodon} target
     * needs {@code ROLE_MASTODON}; {@code internal}/absent needs only the
     * ROLE_USER floor. The SpEL reads the validated request body's platform. The
     * caller's authorities are forwarded to the service so it re-checks the same
     * rule (service leg / defence-in-depth).
     *
     * @param jwt  the already-validated Casdoor JWT
     * @param body the validated block request (target + optional platform)
     * @return a {@link Mono} wrapping a result map with keys {@code pushed}
     *         (boolean) and {@code external} ({@code live}, {@code stubbed}, or
     *         {@code n/a})
     */
    @Operation(
            summary = "Create a self-block (durable row + best-effort external push). Platform-role gated.",
            description = """
                    Records a durable <code>user_block</code> row under the JWT subject,
                    then best-effort pushes to the external homeserver (Matrix/Mastodon; STUBBED by default).
                    The row is the source of truth even if the external push is stubbed or fails.

                    <h4>Caller-role access matrix</h4>
                    <table>
                      <tr><th>Platform</th><th>Required role (API leg + service leg)</th></tr>
                      <tr><td>internal (or absent)</td><td>ROLE_USER floor — no platform role needed</td></tr>
                      <tr><td>matrix</td><td>ROLE_MATRIX (platform access role)</td></tr>
                      <tr><td>mastodon</td><td>ROLE_MASTODON (platform access role)</td></tr>
                    </table>
                    The rule is enforced by <code>@PreAuthorize</code> (API leg) AND re-checked in
                    <code>BlockService</code> (service leg / defence-in-depth).
                    """)
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Block recorded. 'pushed' indicates whether a live external push ran. 'external' is 'live', 'stubbed', or 'n/a'."),
        @ApiResponse(responseCode = "400", description = "Missing target, blank platform, or platform not in matrix|mastodon|internal."),
        @ApiResponse(responseCode = "401", description = "Missing or invalid Casdoor JWT."),
        @ApiResponse(responseCode = "403", description = "ROLE_MATRIX required for platform=matrix; ROLE_MASTODON for platform=mastodon (API leg + service leg re-check)."),
        @ApiResponse(responseCode = "500", description = "Database error writing the block row.")
    })
    @PostMapping("/blocks")
    @PreAuthorize("(#body.platform() == 'matrix' and hasRole('MATRIX')) "
            + "or (#body.platform() == 'mastodon' and hasRole('MASTODON')) "
            + "or (#body.platform() != 'matrix' and #body.platform() != 'mastodon')")
    public Mono<Map<String, Object>> block(@AuthenticationPrincipal Jwt jwt,
                                           @Valid @RequestBody BlockRequest body) {
        // Gather the caller's Spring authority names and forward them to the service
        // so the platform-role gate is re-checked there (defence-in-depth, service leg).
        return callerRoles().flatMap(roles ->
                blocks.block(jwt.getSubject(), body.target(), body.platform(),
                        principalDomain.forScope(jwt), roles));
    }

    // -------------------------------------------------------------------------
    // Delete: remove one of the caller's own blocks
    // -------------------------------------------------------------------------

    /**
     * Removes one of the caller's self-block rows, identified by its UUID.
     * The service validates that the row belongs to the JWT subject and the caller's
     * domain before deleting.
     *
     * @param jwt the already-validated Casdoor JWT
     * @param id  the UUID of the block row to remove (path variable, validated as UUID)
     * @return a {@link Mono} that completes with HTTP 204 No Content on success
     */
    @Operation(summary = "Remove one of my self-blocks (scoped to me + id).")
    @ApiResponses({
        @ApiResponse(responseCode = "204", description = "Block removed."),
        @ApiResponse(responseCode = "400", description = "id is not a valid UUID."),
        @ApiResponse(responseCode = "401", description = "Missing or invalid Casdoor JWT."),
        @ApiResponse(responseCode = "404", description = "No such block for this user (or wrong domain)."),
        @ApiResponse(responseCode = "500", description = "Database error.")
    })
    @DeleteMapping("/blocks/{id}")
    public Mono<ResponseEntity<Void>> unblock(@AuthenticationPrincipal Jwt jwt,
                                              @PathVariable @Pattern(regexp = ValidationPatterns.BLOCK_ID,
                                                      message = "id must be a UUID") String id) {
        return blocks.unblock(jwt.getSubject(), id, principalDomain.forScope(jwt))
                .thenReturn(ResponseEntity.noContent().build());
    }

    // -------------------------------------------------------------------------
    // Recommend: start the USER->MOD->ADMIN instance-block chain
    // -------------------------------------------------------------------------

    /**
     * Recommend an instance block. Requires a homeserver platform role
     * ({@code ROLE_MATRIX} OR {@code ROLE_MASTODON}) at the method level (API leg);
     * the service re-checks the same (service leg). Only a platform participant
     * recommends an instance block.
     *
     * @param jwt  the already-validated Casdoor JWT
     * @param body the validated recommend request ({@code instance} + optional {@code reason})
     * @return a {@link Mono} wrapping a result map describing the submission outcome
     */
    @Operation(summary = "Recommend an instance block (starts the USER->MOD->ADMIN chain via federation-api). Requires a platform role.")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Instance-block recommendation submitted to federation-api. Starts the USER->MOD->ADMIN chain."),
        @ApiResponse(responseCode = "400", description = "Missing instance."),
        @ApiResponse(responseCode = "401", description = "Missing or invalid Casdoor JWT."),
        @ApiResponse(responseCode = "403", description = "Caller lacks ROLE_MATRIX or ROLE_MASTODON (API leg + service leg re-check)."),
        @ApiResponse(responseCode = "502", description = "federation-api unreachable or returned an error.")
    })
    @PostMapping("/recommend-instance-block")
    @PreAuthorize("hasAnyRole('MATRIX', 'MASTODON')")
    public Mono<Map<String, Object>> recommendInstanceBlock(@AuthenticationPrincipal Jwt jwt,
                                                            @Valid @RequestBody RecommendRequest body) {
        // Gather the caller's Spring authority names and forward them to the service
        // so the platform-role gate is re-checked there (defence-in-depth, service leg).
        return callerRoles().flatMap(roles ->
                blocks.recommendInstanceBlock(jwt.getSubject(), body.instance(), body.reason(), roles));
    }

    // -------------------------------------------------------------------------
    // Internal helpers
    // -------------------------------------------------------------------------

    /**
     * The caller's granted authority names from the reactive security context —
     * forwarded to the service so the platform-role gate is re-checked there
     * (defence-in-depth). Defaults to the empty set if (unexpectedly) no
     * authentication is in context; the service then forbids any platform action.
     *
     * @return a {@link Mono} of an immutable set of authority strings (e.g.
     *         {@code ROLE_USER}, {@code ROLE_MATRIX})
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
