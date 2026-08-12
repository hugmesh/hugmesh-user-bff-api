package net.hugmesh.userbff.status;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;
import net.hugmesh.userbff.security.PrincipalDomain;
import net.hugmesh.userbff.silence.SelfSilenceRepository;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Polling endpoint for the caller's own account status — roles, domain, and self-silence
 * state. Derived entirely from the already-validated JWT authorities + the caller's own
 * {@code self_silence} row (owner == JWT subject, no BOLA).
 *
 * <p>GET {@code /bff/user/status} — call at whatever interval the UI prefers to detect
 * account status changes (e.g. suspension removes roles from Casdoor, so the NEXT token
 * refresh reflects the change; the gateway's revocation filter covers in-flight JWTs).
 * No write path exists here: this endpoint is entirely safe to cache or poll.
 */
@Tag(name = "Account status", description = "Polling endpoint for the caller's own account status (roles, domain, silence).")
@RestController
@RequestMapping("/bff/user")
@PreAuthorize("hasRole('USER')")
public class AccountStatusController {

    private final SelfSilenceRepository silenceRepo;
    private final PrincipalDomain principalDomain;

    public AccountStatusController(SelfSilenceRepository silenceRepo, PrincipalDomain principalDomain) {
        this.silenceRepo = silenceRepo;
        this.principalDomain = principalDomain;
    }

    @Operation(summary = "Caller's own account status — active roles, domain scope, and self-silence state.")
    @GetMapping("/status")
    public Mono<Map<String, Object>> status(@AuthenticationPrincipal Jwt jwt, Authentication auth) {
        String sub = jwt.getSubject();
        String domain = principalDomain.forScope(jwt);
        List<String> roles = auth.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .filter(a -> a.startsWith("ROLE_"))
                .map(a -> a.substring("ROLE_".length()))
                .toList();

        return silenceRepo.find(sub, domain)
                .map(s -> buildStatus(sub, domain, roles, s.active(), s.expiresAt()))
                .defaultIfEmpty(buildStatus(sub, domain, roles, false, null));
    }

    private static Map<String, Object> buildStatus(String sub, String domain, List<String> roles,
                                                    boolean silenced, Instant silenceExpiresAt) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("sub", sub);
        out.put("domain", domain != null ? domain : "default");
        out.put("roles", roles);
        out.put("silenced", silenced);
        if (silenceExpiresAt != null) {
            out.put("silenceExpiresAt", silenceExpiresAt.toString());
        }
        return out;
    }
}
