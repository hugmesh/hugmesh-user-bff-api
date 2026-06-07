package systems.snapdragon.userbff.preference;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

import java.util.Map;

/**
 * Owner-scoped home/getting-started-guide preference. The role home views (in the
 * paired snapdragon-user-ui) call GET to decide whether to show the welcome guide,
 * and POST/PUT dismiss once the user has seen it — so the guide shows only on first
 * visit. The owner is ALWAYS the JWT subject; a user can only read/write their own
 * guide state. ROLE_USER floor + {@code @PreAuthorize} defence-in-depth.
 */
@Tag(name = "Home guide", description = "Per-user home/getting-started guide dismissal (owner = JWT subject).")
@RestController
@RequestMapping("/bff/user/home-guide")
@PreAuthorize("hasRole('USER')")
public class HomeGuideController {

    private final HomeGuideService guides;

    public HomeGuideController(HomeGuideService guides) {
        this.guides = guides;
    }

    @Operation(summary = "Is the named guide dismissed for me? (default guide = 'home')")
    @GetMapping
    public Mono<Map<String, Object>> status(@AuthenticationPrincipal Jwt jwt,
                                            @RequestParam(value = "guide", required = false) String guide) {
        String g = (guide == null || guide.isBlank()) ? HomeGuideService.DEFAULT_GUIDE : guide;
        return guides.isDismissed(jwt.getSubject(), g)
                .map(dismissed -> Map.of("guide", g, "dismissed", dismissed));
    }

    @Operation(summary = "Dismiss the named guide for me (idempotent).")
    @PostMapping("/dismiss")
    public Mono<Map<String, Object>> dismiss(@AuthenticationPrincipal Jwt jwt,
                                             @RequestParam(value = "guide", required = false) String guide) {
        String g = (guide == null || guide.isBlank()) ? HomeGuideService.DEFAULT_GUIDE : guide;
        return guides.dismiss(jwt.getSubject(), g)
                .thenReturn(Map.of("guide", g, "dismissed", true));
    }

    @Operation(summary = "Dismiss the named guide for me (PUT alias of /dismiss).")
    @PutMapping("/dismiss")
    public Mono<Map<String, Object>> dismissPut(@AuthenticationPrincipal Jwt jwt,
                                                @RequestParam(value = "guide", required = false) String guide) {
        return dismiss(jwt, guide);
    }

    @Operation(summary = "Re-show (un-dismiss) the named guide for me.")
    @DeleteMapping("/dismiss")
    public Mono<Map<String, Object>> reset(@AuthenticationPrincipal Jwt jwt,
                                           @RequestParam(value = "guide", required = false) String guide) {
        String g = (guide == null || guide.isBlank()) ? HomeGuideService.DEFAULT_GUIDE : guide;
        return guides.reset(jwt.getSubject(), g)
                .thenReturn(Map.of("guide", g, "dismissed", false));
    }
}
