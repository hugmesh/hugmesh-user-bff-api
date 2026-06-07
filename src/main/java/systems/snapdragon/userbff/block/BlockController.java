package systems.snapdragon.userbff.block;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

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
 */
@Tag(name = "Self-block", description = "The caller's OWN blocks (owner = JWT subject) + instance-block recommendation.")
@RestController
@RequestMapping("/bff/user")
@PreAuthorize("hasRole('USER')")
public class BlockController {

    private final BlockService blocks;

    public BlockController(BlockService blocks) {
        this.blocks = blocks;
    }

    @Operation(summary = "List my self-blocks.")
    @GetMapping("/blocks")
    public Flux<UserBlock> mine(@AuthenticationPrincipal Jwt jwt) {
        return blocks.list(jwt.getSubject());
    }

    @Operation(summary = "Create a self-block (durable row + best-effort external push).")
    @PostMapping("/blocks")
    public Mono<Map<String, Object>> block(@AuthenticationPrincipal Jwt jwt,
                                           @RequestBody Map<String, String> body) {
        return blocks.block(jwt.getSubject(), body.get("target"), body.get("platform"));
    }

    @Operation(summary = "Remove one of my self-blocks (scoped to me + id).")
    @DeleteMapping("/blocks/{id}")
    public Mono<ResponseEntity<Void>> unblock(@AuthenticationPrincipal Jwt jwt, @PathVariable String id) {
        return blocks.unblock(jwt.getSubject(), id).thenReturn(ResponseEntity.noContent().build());
    }

    @Operation(summary = "Recommend an instance block (starts the USER->MOD->ADMIN chain via federation-api).")
    @PostMapping("/recommend-instance-block")
    public Mono<Map<String, Object>> recommendInstanceBlock(@AuthenticationPrincipal Jwt jwt,
                                                            @RequestBody Map<String, String> body) {
        return blocks.recommendInstanceBlock(jwt.getSubject(), body.get("instance"), body.get("reason"));
    }
}
