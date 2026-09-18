package net.hugmesh.userbff.config;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import net.hugmesh.commons.config.TenancyResourceServerConfig;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.userbff.testsupport.TestIssuer;

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
 * {@code /bff/register/google}, {@code /bff/register/discord},
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
                net.hugmesh.commons.config.TenancyResolvers.tenantResolver(tenancy);
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

    // ── INVITE-GATED SELF-REGISTRATION (LegacyPathParityController) ────────────

    /**
     * {@code POST /bff/register/google} and {@code /bff/register/discord} are permitAll for the
     * same reason {@code /bff/register} is: registration is PRE-AUTHENTICATION, so the caller
     * has no token to present. The gate that decides who may register is admin-bff's
     * domain-scoped ALLOWLIST, consulted before any account is created — permitAll only exposes
     * the route. Operator decisions 25 + 40 on hugmesh-generator#347 sent both paths here on
     * BOTH gateway route tables.
     */
    @Test
    void registerGoogle_isReachable_withoutJwt() {
        client.post().uri("/bff/register/google").exchange().expectStatus().isOk();
    }

    @Test
    void registerDiscord_isReachable_withoutJwt() {
        client.post().uri("/bff/register/discord").exchange().expectStatus().isOk();
    }

    /**
     * The permit is scoped to those two EXACT paths, NOT the {@code /bff/register/**} subtree.
     * This is not style: admin-bff owns {@code POST /bff/register/complete} — registration
     * stage 2, an AUTHENTICATED mutation that flips {@code registrationComplete} — under the
     * same prefix, and a subtree permit here would expose that sibling anonymously on this BFF
     * the moment anything routes it here. Both probes exist in the probe controller, so a 401
     * is a genuine security decision and not a 404 in disguise.
     */
    @Test
    void registerSubtree_isNotBlanketPermitted_anonymousIs401() {
        client.post().uri("/bff/register/_probe").exchange().expectStatus().isUnauthorized();
        client.post().uri("/bff/register/complete").exchange().expectStatus().isUnauthorized();
    }

    // ── ANONYMOUS PASSWORD RESET — permitAll for the same reason /bff/login is ──

    /**
     * A locked-out caller has NO session and NO current password, so requiring either to
     * reach the reset would be the lock-out itself. Both legs must be reachable
     * anonymously. (In production they still 503 while
     * {@code casdoor.password-reset.enabled=false} — permitAll exposes the route, it
     * enables nothing.)
     */
    @Test
    void passwordResetRequest_isReachable_withoutJwt() {
        client.post().uri("/bff/password-reset/request").exchange().expectStatus().isOk();
    }

    @Test
    void passwordResetConfirm_isReachable_withoutJwt() {
        client.post().uri("/bff/password-reset/confirm").exchange().expectStatus().isOk();
    }

    /**
     * The permit is scoped to the two EXACT paths, NOT the {@code /bff/password-reset/**}
     * subtree — so a sibling endpoint added under that prefix later cannot inherit
     * anonymity by accident. This probe path exists in the probe controller (it would 200
     * if the security layer admitted it), so a 401 here is a genuine security decision and
     * not a 404 in disguise.
     */
    @Test
    void passwordResetSubtree_isNotBlanketPermitted_anonymousIs401() {
        client.post().uri("/bff/password-reset/_probe").exchange().expectStatus().isUnauthorized();
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
                "/bff/register/google", "/bff/register/discord",
                "/bff/register/complete", "/bff/register/_probe",
                "/bff/password-reset/request", "/bff/password-reset/confirm",
                "/bff/password-reset/_probe",
                "/bff/me", "/bff/user/_probe",
        })
        Mono<String> ok() {
            return Mono.just("ok");
        }
    }
}
