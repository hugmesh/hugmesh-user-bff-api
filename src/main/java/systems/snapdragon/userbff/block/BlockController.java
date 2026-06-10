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
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.snapdragon.userbff.web.ValidationPatterns;

import java.util.Map;

/**
 * Owner-scoped self-blocking + instance-block recommendation. The owner is ALWAYS
 * the JWT subject — never a body/path field — so a user can only ever
 * read/create/delete their OWN blocks. ROLE_USER floor + {@code @PreAuthorize}
 * defence-in-depth.
 *
 * <ul>
 *   <li>GET/POST/DELETE {@code /blocks} — the caller's own self-blocks (durable
 *       row + best-effort external Matrix/Mastodon push, STUBBED by default);</li>
 *   <li>POST {@code /recommend-instance-block} — starts the USER->MOD->ADMIN
 *       instance-block chain via federation-api (a recommendation, not a block).</li>
 * </ul>
 *
 * <p>Request bodies are typed + {@code @Valid}-ated records (was an untyped
 * {@code Map}) so a missing {@code target}/{@code instance} or a bad
 * {@code platform} is a clean 400 with a field error BEFORE the service / DB CHECK
 * (005 {@code ck_user_block_platform}); the service still re-checks as
 * defence-in-depth.
 */
@Tag(name = "Self-block", description = "The caller's OWN blocks (owner = JWT subject) + instance-block recommendation.")
@RestController
@RequestMapping("/bff/user")
@PreAuthorize("hasRole('USER')")
@Validated
public class BlockController {

    private final BlockService blocks;

    public BlockController(BlockService blocks) {
        this.blocks = blocks;
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
        return blocks.list(jwt.getSubject());
    }

    @Operation(summary = "Create a self-block (durable row + best-effort external push).")
    @PostMapping("/blocks")
    public Mono<Map<String, Object>> block(@AuthenticationPrincipal Jwt jwt,
                                           @Valid @RequestBody BlockRequest body) {
        return blocks.block(jwt.getSubject(), body.target(), body.platform());
    }

    @Operation(summary = "Remove one of my self-blocks (scoped to me + id).")
    @DeleteMapping("/blocks/{id}")
    public Mono<ResponseEntity<Void>> unblock(@AuthenticationPrincipal Jwt jwt,
                                              @PathVariable @Pattern(regexp = ValidationPatterns.BLOCK_ID,
                                                      message = "id must be a UUID") String id) {
        return blocks.unblock(jwt.getSubject(), id).thenReturn(ResponseEntity.noContent().build());
    }

    @Operation(summary = "Recommend an instance block (starts the USER->MOD->ADMIN chain via federation-api).")
    @PostMapping("/recommend-instance-block")
    public Mono<Map<String, Object>> recommendInstanceBlock(@AuthenticationPrincipal Jwt jwt,
                                                            @Valid @RequestBody RecommendRequest body) {
        return blocks.recommendInstanceBlock(jwt.getSubject(), body.instance(), body.reason());
    }
}
