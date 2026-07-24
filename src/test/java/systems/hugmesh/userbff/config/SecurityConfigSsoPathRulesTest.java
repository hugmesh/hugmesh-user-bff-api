package systems.hugmesh.userbff.config;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import systems.hugmesh.commons.config.TenancyResourceServerConfig;
import systems.hugmesh.commons.security.DomainRegistry;
import systems.hugmesh.userbff.testsupport.TestIssuer;

/**
 * Path-rule slice for the SSO LOGIN RELOCATION — the new {@link SecurityConfig}
 * permitAll rules driven THROUGH the real prod filter chain via
 * {@link SecuritySliceSupport#sliceClient} (NO full Spring Boot context, so a stand-in
 * probe controller can reuse the REAL login paths without colliding with the production
 * controllers under a component scan). Uses the multi-issuer resolver wiring of
 * {@link SecurityConfigPathGateSliceTest} (in-process {@link TestIssuer} brands) so the
 * chain builds with NO network JWKS fetch.
 *
 * <p>Proves the pre-auth login entrypoints ({@code /bff/login}, {@code /bff/register},
 * {@code /bff/session}) are reachable WITHOUT a Casdoor JWT (they
 * are how a caller obtains a session), while {@code /bff/me} and the {@code /bff/user/**}
 * floor STILL require authentication (anonymous ⇒ 401). "Reachable" means the SECURITY
 * layer admits the request — in production every one of these handlers ships dark
 * (503/fail-closed when {@code app.bff.oidc.enabled=false}), so permitAll only exposes
 * the route, it authenticates no one.
 */
class SecurityConfigSsoPathRulesTest extends SecuritySliceSupport {

    private TestIssuer issuer;
    private TestIssuer issuer2;   // a second trusted issuer so isMultiIssuer() holds
    private WebTestClient client;

    @BeforeEach
    void setUp() {
        issuer = new TestIssuer();
        issuer2 = new TestIssuer();
        String issuersCsv = issuer.issuerUri() + "=brandx," + issuer2.issuerUri() + "=brandy";
        DomainRegistry registry = new DomainRegistry(issuer.issuerUri(), issuersCsv);
        TenancyResourceServerConfig tenancy = new TenancyResourceServerConfig(registry, "", "", false, 600000L);
        ReactiveAuthenticationManagerResolver<ServerWebExchange> resolver =
                systems.hugmesh.commons.config.TenancyResolvers.tenantResolver(tenancy);
        client = sliceClient(registry, provider(resolver), new SsoProbeController());
    }

    @AfterEach
    void tearDown() {
        issuer.close();
        issuer2.close();
    }

    // ── PRE-AUTH SSO login surface — permitAll, reachable anonymously ──────────

    @Test
    void login_isReachable_withoutJwt() {
        client.post().uri("/bff/login").exchange().expectStatus().isOk();
    }

    @Test
    void register_isReachable_withoutJwt() {
        client.post().uri("/bff/register").exchange().expectStatus().isOk();
    }

    @Test
    void session_isReachable_withoutJwt() {
        client.delete().uri("/bff/session").exchange().expectStatus().isOk();
    }

    // ── /bff/me + /bff/user/** still behind the authenticated() floor ──────────

    @Test
    void me_requiresAuth_anonymousIs401() {
        // /bff/me is deliberately NOT permitAll — it falls through to the
        // anyExchange().authenticated() floor (matches admin-bff).
        client.get().uri("/bff/me").exchange().expectStatus().isUnauthorized();
    }

    @Test
    void userSurface_stillRequiresAuth_anonymousIs401() {
        client.get().uri("/bff/user/_probe").exchange().expectStatus().isUnauthorized();
    }

    /** Maps every path the slice exercises so an ALLOWED request resolves to 200
     *  (instead of a 404 that could mask a missing security decision). Nested so the
     *  component scan never sees it (it is supplied to the slice client explicitly). */
    @RestController
    static class SsoProbeController {
        @RequestMapping({
                "/bff/login", "/bff/register", "/bff/session",
                "/bff/me", "/bff/user/_probe",
        })
        Mono<String> ok() {
            return Mono.just("ok");
        }
    }
}
