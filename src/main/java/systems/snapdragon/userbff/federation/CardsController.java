package systems.snapdragon.userbff.federation;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.MediaType;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * Owner-scoped "cards" = the caller's OWN federation bundles ({@code user_modules}
 * in snapdragon-federation-api). This controller is a thin reactive pass-through to
 * {@link FederationApiClient}; owner-enforcement is preserved because the
 * {@code FederationWebClientConfig} filter forwards the caller's Casdoor JWT, so
 * federation-api scopes {@code /mine} (and records ownership on PUT) to the same
 * subject — there is no way to address another user's cards.
 *
 * <p>ROLE_USER floor + {@code @PreAuthorize} defence-in-depth.
 */
@Tag(name = "Cards", description = "The caller's OWN federation bundles (owner = JWT subject), via snapdragon-federation-api.")
@RestController
@RequestMapping("/bff/user/cards")
@PreAuthorize("hasRole('USER')")
public class CardsController {

    private final FederationApiClient federation;

    public CardsController(FederationApiClient federation) {
        this.federation = federation;
    }

    @Operation(summary = "List my cards (my federation bundles).")
    @GetMapping
    public Flux<UserModuleCard> mine(@AuthenticationPrincipal Jwt jwt) {
        // jwt unused here for scoping (the forwarded token scopes upstream), but
        // required so the route stays authenticated + the contract is explicit.
        return federation.listMine();
    }

    @Operation(summary = "List versions of one of my cards by slug.")
    @GetMapping("/{slug}")
    public Flux<UserModuleCard> bySlug(@AuthenticationPrincipal Jwt jwt, @PathVariable String slug) {
        return federation.listBySlug(slug);
    }

    @Operation(
            summary = "Publish (create/update) a card bundle for a slug.",
            description = "Body is the single entry file (octet-stream). federation-api content-hashes it, "
                    + "records a user_modules row under ME (forwarded JWT), and supersedes the prior version.")
    @PutMapping(value = "/{slug}", consumes = MediaType.APPLICATION_OCTET_STREAM_VALUE)
    public Mono<UserModuleCard> put(@AuthenticationPrincipal Jwt jwt,
                                    @PathVariable String slug,
                                    @RequestParam(value = "entryFile", required = false) String entryFile,
                                    @RequestParam(value = "visibility", required = false) String visibility,
                                    @RequestParam(value = "manifest", required = false) String manifestJson,
                                    @RequestBody(required = false) byte[] body) {
        return federation.put(slug, entryFile, visibility, manifestJson, body);
    }
}
