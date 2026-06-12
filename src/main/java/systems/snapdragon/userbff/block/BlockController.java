package systems.snapdragon.userbff.block;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
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
 */
@Tag(name = "Self-block", description = "The caller's OWN blocks (owner = JWT subject) + instance-block recommendation.")
@RestController
@RequestMapping("/bff/user")
@PreAuthorize("hasRole('USER')")
@Validated
public class BlockController {

    private final BlockService blocks;
    private final PrincipalDomain principalDomain;

    public BlockController(BlockService blocks, PrincipalDomain principalDomain) {
        this.blocks = blocks;
        this.principalDomain = principalDomain;
    }

    /**
     * Create-self-block body. {@code target} (the blocked identity) is required;
     * {@code platform} is optional (defaults to {@code internal} in the service)
     * but, when supplied, must be one of the {@code user_block.platform} vocabulary
     * — mirrors the 005 CHECK + {@code UserBlock.validPlatform}.
     */
    public record BlockRequest(
            @NotBlank(message = "target is required")
            @Size(max = 512, message = "target must be at most 512 chars") String target,
            @Pattern(regexp = ValidationPatterns.PLATFORM,
                    message = "platform must be matrix|mastodon|internal") String platform) {}

    /** Recommend-instance-block body. {@code instance} (the homeserver/domain) is
     *  required; {@code reason} is free text. */
    public record RecommendRequest(
            @NotBlank(message = "instance is required")
            @Size(max = 512, message = "instance must be at most 512 chars") String instance,
            @Size(max = 2048, message = "reason must be at most 2048 chars") String reason) {}

    @Operation(summary = "List my self-blocks.")
    @GetMapping("/blocks")
    public Flux<UserBlock> mine(@AuthenticationPrincipal Jwt jwt) {
        return blocks.list(jwt.getSubject(), principalDomain.forScope(jwt));
    }

    /**
     * Create a self-block. PLATFORM-ROLE GATED at the method level (API leg): a
     * {@code matrix} target needs {@code ROLE_MATRIX}, a {@code mastodon} target
     * needs {@code ROLE_MASTODON}; {@code internal}/absent needs only the
     * ROLE_USER floor. The SpEL reads the validated request body's platform. The
     * caller's authorities are forwarded to the service so it re-checks the same
     * rule (service leg / defence-in-depth).
     */
    @Operation(summary = "Create a self-block (durable row + best-effort external push). Platform-role gated.")
    @PostMapping("/blocks")
    @PreAuthorize("(#body.platform() == 'matrix' and hasRole('MATRIX')) "
            + "or (#body.platform() == 'mastodon' and hasRole('MASTODON')) "
            + "or (#body.platform() != 'matrix' and #body.platform() != 'mastodon')")
    public Mono<Map<String, Object>> block(@AuthenticationPrincipal Jwt jwt,
                                           @Valid @RequestBody BlockRequest body) {
        return callerRoles().flatMap(roles ->
                blocks.block(jwt.getSubject(), body.target(), body.platform(),
                        principalDomain.forScope(jwt), roles));
    }

    @Operation(summary = "Remove one of my self-blocks (scoped to me + id).")
    @DeleteMapping("/blocks/{id}")
    public Mono<ResponseEntity<Void>> unblock(@AuthenticationPrincipal Jwt jwt,
                                              @PathVariable @Pattern(regexp = ValidationPatterns.BLOCK_ID,
                                                      message = "id must be a UUID") String id) {
        return blocks.unblock(jwt.getSubject(), id, principalDomain.forScope(jwt))
                .thenReturn(ResponseEntity.noContent().build());
    }

    /**
     * Recommend an instance block. Requires a homeserver platform role
     * ({@code ROLE_MATRIX} OR {@code ROLE_MASTODON}) at the method level (API leg);
     * the service re-checks the same (service leg). Only a platform participant
     * recommends an instance block.
     */
    @Operation(summary = "Recommend an instance block (starts the USER->MOD->ADMIN chain via federation-api). Requires a platform role.")
    @PostMapping("/recommend-instance-block")
    @PreAuthorize("hasAnyRole('MATRIX', 'MASTODON')")
    public Mono<Map<String, Object>> recommendInstanceBlock(@AuthenticationPrincipal Jwt jwt,
                                                            @Valid @RequestBody RecommendRequest body) {
        return callerRoles().flatMap(roles ->
                blocks.recommendInstanceBlock(jwt.getSubject(), body.instance(), body.reason(), roles));
    }

    /**
     * The caller's granted authority names from the reactive security context —
     * forwarded to the service so the platform-role gate is re-checked there
     * (defence-in-depth). Defaults to the empty set if (unexpectedly) no
     * authentication is in context; the service then forbids any platform action.
     */
    private static Mono<Set<String>> callerRoles() {
        return ReactiveSecurityContextHolder.getContext()
                .map(ctx -> ctx.getAuthentication().getAuthorities().stream()
                        .map(a -> a.getAuthority())
                        .collect(Collectors.toUnmodifiableSet()))
                .defaultIfEmpty(Set.of());
    }
}
