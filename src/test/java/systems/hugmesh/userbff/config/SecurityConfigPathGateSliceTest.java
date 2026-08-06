package systems.hugmesh.userbff.config;

import systems.hugmesh.commons.config.TenancyResourceServerConfig;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import systems.hugmesh.commons.security.DomainRegistry;
import systems.hugmesh.userbff.testsupport.TestIssuer;

import java.util.List;

/**
 * Coarse PATH-GATE slice — the {@link SecurityConfig} {@code authorizeExchange} policy
 * (the prod {@code !dev & !test} chain) end-to-end through the REAL filter chain,
 * driven by REAL RSA-signed tokens from in-process {@link TestIssuer} brands (the only
 * no-network decoder seam). Mirrors hugmesh-gateway's keystone
 * {@code SecurityConfigPathGateSliceTest}; only the path/role table is this BFF's.
 *
 * <p>The existing {@code SecurityConfigPathRulesTest} covers the same matchers with
 * {@code mockJwt()} synthetic principals (no real decoder). THIS slice complements it
 * by proving the multi-issuer UNKNOWN-iss 401 fail-closed reaches the gate
 * END-TO-END (real token → real resolver → real authorizeExchange), which a mockJwt
 * test cannot exercise.
 *
 * <p>This BFF's {@code commonRoutes()} table:
 * <ul>
 *   <li><b>ANONYMOUS ALLOW</b> — {@code /actuator/health}, {@code /actuator/info} are
 *       public so k8s/Docker healthchecks need no token;</li>
 *   <li><b>ROLE_SERVICE-only</b> — {@code /bff/user/internal/**} is the
 *       service-to-service surface (the IDOR guard: a human JWT, even ADMIN/SUPERADMIN,
 *       must be FORBIDDEN — only the platform service-account role admits);</li>
 *   <li><b>ROLE_USER floor</b> — {@code /bff/user/**} is any-authenticated (the
 *       converter floors every principal to ROLE_USER);</li>
 *   <li><b>ANONYMOUS DENY</b> — {@code anyExchange().authenticated()} 401s an
 *       unauthenticated caller on any gated path.</li>
 * </ul>
 *
 * <p>Categories per the comprehensive test standard: the ROLE_SERVICE gate is
 * CROSS-USER DENY (a human can never reach the system-acting-on-a-user's-behalf
 * surface); the floor/anonymous rows are USER-SITUATIONAL ALLOW/DENY.
 */
class SecurityConfigPathGateSliceTest extends SecuritySliceSupport {

    private TestIssuer issuer;
    private TestIssuer issuer2;   // a second trusted issuer so isMultiIssuer() holds
    private TestIssuer rogue;     // NOT trusted — for the end-to-end unknown-iss 401
    private WebTestClient client;

    @BeforeEach
    void setUp() {
        issuer = new TestIssuer();
        issuer2 = new TestIssuer();
        rogue = new TestIssuer();
        String issuersCsv = issuer.issuerUri() + "=brandx," + issuer2.issuerUri() + "=brandy";
        DomainRegistry registry = new DomainRegistry(issuer.issuerUri(), issuersCsv);
        TenancyResourceServerConfig tenancy = new TenancyResourceServerConfig(registry, "", "", false, 600000L);
        ReactiveAuthenticationManagerResolver<ServerWebExchange> resolver =
                systems.hugmesh.commons.config.TenancyResolvers.tenantResolver(tenancy);
        client = sliceClient(registry, provider(resolver), new ProbeController());
    }

    @AfterEach
    void tearDown() {
        issuer.close();
        issuer2.close();
        rogue.close();
    }

    private WebTestClient.RequestHeadersSpec<?> as(List<String> roles, String path) {
        String token = issuer.mint("p-" + String.join("-", roles), roles);
        return client.get().uri(path).header("Authorization", "Bearer " + token);
    }

    // ── multi-issuer UNKNOWN-iss 401, END-TO-END through authorizeExchange ─────

    @Test
    void unknownIssuerToken_is401_endToEnd_onGatedPath() {
        // A real, correctly-signed token from an issuer NOT in app.tenancy.issuers,
        // presented to a gated path, is 401'd by the resolver BEFORE the
        // authorizeExchange floor is even evaluated — the fail-closed posture holds
        // all the way through the real filter chain (not just at the resolver in
        // isolation). The token even claims superadmin — it still cannot cross in.
        String token = rogue.mint("attacker", List.of("admin", "superadmin"));
        client.get().uri("/bff/user/_probe")
                .header("Authorization", "Bearer " + token)
                .exchange()
                .expectStatus().isUnauthorized();
    }

    // ── ANONYMOUS ALLOW — public probe paths ──────────────────────────────────

    @Test
    void anonymous_allowedOn_actuatorHealth() {
        client.get().uri("/actuator/health").exchange().expectStatus().isOk();
    }

    @Test
    void anonymous_allowedOn_actuatorInfo() {
        client.get().uri("/actuator/info").exchange().expectStatus().isOk();
    }

    // ── ROLE_SERVICE gate — /bff/user/internal/** (the IDOR guard) ────────────

    @Test
    void internalSurface_serviceRole_isAllowed() {
        // ROLE_SERVICE is the platform service-account role; it reaches the internal
        // deliver surface (200 from the probe).
        as(List.of("service"), "/bff/user/internal/notifications/deliver")
                .exchange().expectStatus().isOk();
    }

    @Test
    void internalSurface_plainUser_isForbidden() {
        // A human user must NEVER reach the internal surface — it takes its target
        // (domain, userSubject) from the BODY, so a human reaching it could spoof a
        // notification to ANY user (an IDOR). 403, not 200.
        as(List.of("user"), "/bff/user/internal/notifications/deliver")
                .exchange().expectStatus().isForbidden();
    }

    @Test
    void internalSurface_admin_isForbidden() {
        // Deliberately NOT hasAnyRole(SERVICE,ADMIN,SUPERADMIN): ADMIN is human-reachable
        // and would re-open the IDOR. Even ADMIN is DENIED here.
        as(List.of("admin"), "/bff/user/internal/notifications/deliver")
                .exchange().expectStatus().isForbidden();
    }

    @Test
    void internalSurface_superadmin_isForbidden() {
        // The role hierarchy (SUPERADMIN > ADMIN/MOD/USER, NO edge to SERVICE) means
        // even SUPERADMIN is DENIED on the internal surface.
        as(List.of("superadmin"), "/bff/user/internal/notifications/deliver")
                .exchange().expectStatus().isForbidden();
    }

    @Test
    void internalSurface_anonymous_isUnauthorized() {
        client.get().uri("/bff/user/internal/notifications/deliver")
                .exchange().expectStatus().isUnauthorized();
    }

    // ── ROLE_USER floor — /bff/user/** any-authenticated ──────────────────────

    @Test
    void userSurface_authenticatedUser_isAllowed() {
        as(List.of("user"), "/bff/user/_probe").exchange().expectStatus().isOk();
    }

    @Test
    void userSurface_anonymous_isUnauthorized() {
        // anyExchange().authenticated() floor: an unauthenticated caller 401s.
        client.get().uri("/bff/user/_probe").exchange().expectStatus().isUnauthorized();
    }

    // ── ANONYMOUS DENY — the authenticated() floor on an ungoverned path ───────

    @Test
    void anonymous_deniedOn_arbitraryGatedPath() {
        client.get().uri("/some/other/path").exchange().expectStatus().isUnauthorized();
    }

    /** Maps every path the slice exercises so an ALLOWED request resolves to 200
     *  (instead of a 404 that could mask a missing security decision). */
    @RestController
    static class ProbeController {
        @RequestMapping({
                "/actuator/health", "/actuator/info",
                "/bff/user/internal/notifications/deliver",
                "/bff/user/_probe",
                "/some/other/path",
        })
        Mono<String> ok() {
            return Mono.just("ok");
        }
    }
}
