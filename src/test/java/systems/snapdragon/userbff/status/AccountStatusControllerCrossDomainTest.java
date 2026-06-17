package systems.snapdragon.userbff.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.WebFluxTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;
import systems.snapdragon.userbff.config.SecurityConfig;
import systems.snapdragon.userbff.security.DomainRegistry;
import systems.snapdragon.userbff.security.PrincipalDomain;
import systems.snapdragon.userbff.silence.SelfSilenceRepository;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;

/**
 * Cross-domain HTTP-boundary test for {@link AccountStatusController}
 * ({@code GET /bff/user/status}), with the REAL {@link PrincipalDomain} +
 * {@link DomainRegistry} (multi-issuer). This controller is unique in that it
 * SURFACES the resolved domain in the response body ({@code $.domain}) and the active
 * {@code ROLE_*} authorities ({@code $.roles}) — so the issuer-derived domain and the
 * subject are directly HTTP-observable (not just verified via a service mock).
 *
 * <ul>
 *   <li>anonymous → 401; authenticated-without-ROLE_USER → 403 (silence repo never hit);</li>
 *   <li>brand-X token → {@code $.domain == "brandx"}, {@code $.sub == subject}; the
 *       silence repo is queried with owner==subject / domain "brandx";</li>
 *   <li>brand-Y token → {@code $.domain == "brandy"} (cross-domain isolation);</li>
 *   <li>UNKNOWN issuer (non-SUPERADMIN) → {@code $.domain == "__deny__"} (fail-closed:
 *       a non-matchable scope is reflected to the caller, never a real brand);</li>
 *   <li>SUPERADMIN → repo queried with {@code null} bypass; body reports the
 *       {@code "default"} fallback label (the controller maps null→"default" for the
 *       view only).</li>
 * </ul>
 */
@WebFluxTest(controllers = AccountStatusController.class)
@Import({SecurityConfig.class, PrincipalDomain.class, DomainRegistry.class})
@TestPropertySource(properties = {
        "spring.security.oauth2.resourceserver.jwt.issuer-uri=",
        "app.tenancy.issuers=https://id.brandx.example=brandx,https://id.brandy.example=brandy"
})
class AccountStatusControllerCrossDomainTest {

    private static final String BRANDX = "https://id.brandx.example";
    private static final String BRANDY = "https://id.brandy.example";

    @Autowired WebTestClient client;

    @MockitoBean ReactiveJwtDecoder jwtDecoder;
    @MockitoBean SelfSilenceRepository silenceRepo;

    private static Collection<GrantedAuthority> authorities(String... names) {
        List<GrantedAuthority> out = new ArrayList<>();
        for (String n : names) out.add(new SimpleGrantedAuthority(n));
        return out;
    }

    @Test
    void anonymous_isUnauthorized_repoNeverHit() {
        client.get().uri("/bff/user/status").exchange().expectStatus().isUnauthorized();
        verify(silenceRepo, never()).find(anyString(), any());
    }

    @Test
    void authenticatedWithoutRoleUser_isForbidden_repoNeverHit() {
        client.mutateWith(mockJwt()
                        .jwt(j -> j.subject("alice").issuer(BRANDX))
                        .authorities(authorities("DOMAIN_brandx")))
                .get().uri("/bff/user/status")
                .exchange()
                .expectStatus().isForbidden();
        verify(silenceRepo, never()).find(anyString(), any());
    }

    @Test
    void brandX_surfacesBrandXDomainAndSubject_repoScopedToBrandX() {
        when(silenceRepo.find(eq("alice"), eq("brandx"))).thenReturn(Mono.empty());

        client.mutateWith(mockJwt()
                        .jwt(j -> j.subject("alice").issuer(BRANDX))
                        .authorities(authorities("ROLE_USER", "DOMAIN_brandx")))
                .get().uri("/bff/user/status")
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.sub").isEqualTo("alice")
                .jsonPath("$.domain").isEqualTo("brandx")
                .jsonPath("$.silenced").isEqualTo(false);

        verify(silenceRepo).find("alice", "brandx");
        verify(silenceRepo, never()).find(anyString(), eq("brandy"));
    }

    @Test
    void brandY_surfacesBrandYDomain_neverBrandX() {
        when(silenceRepo.find(eq("carol"), eq("brandy"))).thenReturn(Mono.empty());

        client.mutateWith(mockJwt()
                        .jwt(j -> j.subject("carol").issuer(BRANDY))
                        .authorities(authorities("ROLE_USER", "DOMAIN_brandy")))
                .get().uri("/bff/user/status")
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.domain").isEqualTo("brandy");

        verify(silenceRepo).find("carol", "brandy");
        verify(silenceRepo, never()).find(anyString(), eq("brandx"));
    }

    @Test
    void unknownIssuer_surfacesDenySentinel_failsClosed() {
        when(silenceRepo.find(eq("mallory"), eq("__deny__"))).thenReturn(Mono.empty());

        client.mutateWith(mockJwt()
                        .jwt(j -> j.subject("mallory").issuer("https://evil.attacker.example"))
                        .authorities(authorities("ROLE_USER")))
                .get().uri("/bff/user/status")
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.domain").isEqualTo("__deny__");   // never a real brand

        verify(silenceRepo).find("mallory", "__deny__");
        verify(silenceRepo, never()).find(eq("mallory"), eq("brandx"));
        verify(silenceRepo, never()).find(eq("mallory"), eq("brandy"));
    }

    @Test
    void superadmin_repoNullBypass_bodyReportsDefaultLabel() {
        when(silenceRepo.find(eq("root"), eq(null))).thenReturn(Mono.empty());

        client.mutateWith(mockJwt()
                        .jwt(j -> j.subject("root").issuer(BRANDX).claim("roles", List.of("superadmin")))
                        .authorities(authorities("ROLE_USER", "ROLE_SUPERADMIN", "DOMAIN_brandx")))
                .get().uri("/bff/user/status")
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                // The repo is queried with the null cross-domain bypass; the VIEW maps
                // null -> "default" purely for display (buildStatus), so the body shows
                // "default" while the actual scope was the unscoped bypass.
                .jsonPath("$.domain").isEqualTo("default")
                .jsonPath("$.roles").value(o -> {
                    @SuppressWarnings("unchecked")
                    List<String> roles = (List<String>) o;
                    org.assertj.core.api.Assertions.assertThat(roles).contains("SUPERADMIN", "USER");
                });

        verify(silenceRepo).find("root", null);
    }
}
