package net.hugmesh.userbff.directory;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.Size;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Mono;
import net.hugmesh.commons.security.Roles;
import net.hugmesh.userbff.auth.AdminBffInternalClient;
import net.hugmesh.userbff.auth.AdminBffInternalClient.MeshUserView;
import net.hugmesh.userbff.security.PrincipalDomain;

import java.util.List;

/**
 * The type-to-find box behind "start a chat", "invite to a room" and "invite to a game":
 * {@code GET /bff/user/directory/search?q=&limit=} returns mesh users on the CALLER'S OWN domain, or every
 * domain for a SUPERADMIN.
 *
 * <p>There is deliberately NO {@code domain} parameter: the scope comes from the caller's validated JWT
 * ({@link PrincipalDomain#forScope}, which fails closed for an unresolved issuer), so a member of one
 * domain cannot name another. admin-bff applies the scope, the cap (25) and the minimum fragment (2
 * characters); this adds a per-subject rate limit. Rows are username, Matrix localpart and domain,
 * never an e-mail address.
 */
@RestController
@RequestMapping("/bff/user/directory")
@Validated
public class MemberDirectoryController {

    private final AdminBffInternalClient admin;
    private final PrincipalDomain principalDomain;
    private final DirectoryRateLimiter limiter;

    public MemberDirectoryController(AdminBffInternalClient admin, PrincipalDomain principalDomain,
                                     DirectoryRateLimiter limiter) {
        this.admin = admin;
        this.principalDomain = principalDomain;
        this.limiter = limiter;
    }

    @PreAuthorize("hasRole('USER')")
    @Operation(summary = "Find mesh users by name (own domain; every domain for a superadmin).")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Up to limit matches, best first (empty under 2 characters)."),
        @ApiResponse(responseCode = "401", description = "Missing or invalid Casdoor JWT."),
        @ApiResponse(responseCode = "429", description = "Too many lookups; keep typing slower.")
    })
    @GetMapping("/search")
    public Mono<List<MeshUserView>> search(
            @AuthenticationPrincipal Jwt jwt,
            @RequestParam(name = "q", required = false, defaultValue = "") @Size(max = 200) String q,
            @RequestParam(name = "limit", required = false, defaultValue = "10") @Min(1) @Max(25) int limit) {
        if (!limiter.tryAcquire(jwt.getSubject())) {
            return Mono.error(new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS, "too many lookups"));
        }
        boolean superadmin = Roles.isSuperadmin(jwt);
        String scope = principalDomain.forScope(jwt);   // null = superadmin; "__deny__" = unresolved issuer
        return admin.searchMeshUsers(scope, superadmin, q, limit);
    }
}
