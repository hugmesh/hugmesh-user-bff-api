package net.hugmesh.userbff.config;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.boot.webflux.test.autoconfigure.WebFluxTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * Stand-in controller exposing one endpoint per policy tier so the WebFlux
 * SecurityConfig path-matcher rules are exercised in isolation.
 */
@RestController
class Probes {
    @GetMapping("/actuator/health") String health() { return "UP"; }
    @GetMapping("/actuator/info") String info() { return "info"; }
    // Stand-in for the ROLE_USER-floor surface. A synthetic /bff/user/_probe path
    // (NOT a real controller route) so the @WebFluxTest slice exercises the
    // /bff/user/** matcher without colliding with the real ProfileController when
    // the full @SpringBootTest component-scan loads both.
    @GetMapping("/bff/user/_probe") String userSurface() { return "ok"; }
    // Stand-in for the springdoc-served OpenAPI spec path so the SPEC_PATHS matcher
    // can be exercised in isolation (the real handler is contributed by springdoc).
    @GetMapping("/v3/api-docs") String apiDocs() { return "{}"; }
}

/**
 * Integration test for the reactive {@link SecurityConfig} path rules + the
 * ROLE_USER floor, driven via {@link WebTestClient} with {@code mockJwt()}
 * synthetic authentications. With no active profile the {@code !dev & !test} (prod)
 * filter chain loads, so the springdoc spec path requires ROLE_ADMIN.
 *
 * <ul>
 *   <li>{@code /actuator/health} + {@code /actuator/info} — public.</li>
 *   <li>{@code /bff/user/**} — ROLE_USER floor (any authenticated caller).</li>
 *   <li>{@code /v3/api-docs} — ROLE_ADMIN under prod (never publicly reachable).</li>
 * </ul>
 */
@WebFluxTest(controllers = Probes.class)
@Import(SecurityConfig.class)
class SecurityConfigPathRulesTest {

    @Autowired ApplicationContext context;
    WebTestClient client;

    // Spring Security 7: the mockJwt()/mock* reactive mutators only inject the
    // SecurityContext when the springSecurity() configurer's MutatorFilter is in the
    // chain. A @WebFluxTest-autowired client lacks it (mutator dropped -> 401), so build
    // the client from the ApplicationContext with .apply(springSecurity()).
    @org.junit.jupiter.api.BeforeEach
    void setUpSecuredWebTestClient() {
        client = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    @MockitoBean ReactiveJwtDecoder jwtDecoder;

    @Test
    void health_isPublic() {
        client.get().uri("/actuator/health").exchange().expectStatus().isOk();
    }

    @Test
    void info_isPublic() {
        client.get().uri("/actuator/info").exchange().expectStatus().isOk();
    }

    @Test
    void userSurface_deniedForAnonymous() {
        client.get().uri("/bff/user/_probe").exchange().expectStatus().isUnauthorized();
    }

    @Test
    void userSurface_allowedForAnyAuthenticatedUser() {
        client.mutateWith(mockJwt().authorities(authorities("ROLE_USER")))
                .get().uri("/bff/user/_probe").exchange().expectStatus().isOk();
    }

    // --- OpenAPI spec gating (prod / default profile = neither dev nor test) ---
    @Test
    void apiDocs_deniedForAnonymous_inProd() {
        client.get().uri("/v3/api-docs").exchange().expectStatus().isUnauthorized();
    }

    @Test
    void apiDocs_deniedForPlainUser_inProd() {
        client.mutateWith(mockJwt().authorities(authorities("ROLE_USER")))
                .get().uri("/v3/api-docs").exchange().expectStatus().isForbidden();
    }

    @Test
    void apiDocs_allowedForAdmin_inProd() {
        client.mutateWith(mockJwt().authorities(authorities("ROLE_USER", "ROLE_ADMIN")))
                .get().uri("/v3/api-docs").exchange().expectStatus().isOk();
    }

    @Test
    void apiDocs_allowedForSuperadmin_inProd() {
        // SUPERADMIN (the cross-domain infra super-role) also reaches the admin-gated
        // spec surface — the spec gate is hasAnyRole(ADMIN, SUPERADMIN).
        client.mutateWith(mockJwt().authorities(authorities("ROLE_USER", "ROLE_SUPERADMIN")))
                .get().uri("/v3/api-docs").exchange().expectStatus().isOk();
    }

    private static Collection<GrantedAuthority> authorities(String... names) {
        List<GrantedAuthority> out = new ArrayList<>();
        for (String n : names) out.add(new SimpleGrantedAuthority(n));
        return out;
    }
}
