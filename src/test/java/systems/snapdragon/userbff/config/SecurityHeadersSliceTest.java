package systems.snapdragon.userbff.config;

import systems.snapdragon.commons.config.TenancyResourceServerConfig;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import systems.snapdragon.commons.security.DomainRegistry;
import systems.snapdragon.userbff.testsupport.TestIssuer;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * HARDENED RESPONSE-HEADER slice — proves the {@code .headers(...)} block added to the
 * production {@link SecurityConfig#filterChain} actually emits the API-defensive
 * minimum header set on a real response, driven THROUGH the real filter chain via
 * {@link SecuritySliceSupport#sliceClient} (no full Spring Boot context).
 *
 * <p>This is the regression guard backing the {@code missing-security-headers} nuclei
 * template (OWASP A05 / ASVS V14.4): the BFF previously had {@code headersCalls=0}, so
 * CSP / Referrer-Policy were absent. We assert:
 * <ul>
 *   <li><b>CSP present + locked-down</b> — {@code default-src 'none'; frame-ancestors 'none'}
 *       (a no-document JSON API needs nothing more);</li>
 *   <li><b>Referrer-Policy: no-referrer</b> — Spring default, made explicit;</li>
 *   <li><b>Spring secure defaults KEPT</b> — {@code X-Content-Type-Options: nosniff},
 *       {@code X-Frame-Options: DENY}, {@code Cache-Control} present (NOT disabled);</li>
 *   <li><b>HSTS deliberately ABSENT</b> — this BFF is not the TLS front door, so it must
 *       NOT emit a misleading Strict-Transport-Security over plaintext intra-mesh;</li>
 *   <li><b>headers ride alongside auth</b> — an unauthenticated request to a gated path
 *       still 401s AND still carries the hardened headers (additive, never weakening
 *       the deny-by-default floor).</li>
 * </ul>
 */
class SecurityHeadersSliceTest extends SecuritySliceSupport {

    private TestIssuer issuer;
    private TestIssuer issuer2;   // a second trusted issuer so isMultiIssuer() holds
    private WebTestClient client;

    /** Build the slice over the same REAL in-process multi-issuer decoder seam the
     *  path-gate slice uses (no network — {@code o.jwt(...)} would need to resolve a
     *  live issuer-uri). The header block is profile/issuer-independent, so exercising
     *  it through the real resolver chain is the most faithful posture. */
    @BeforeEach
    void setUp() {
        issuer = new TestIssuer();
        issuer2 = new TestIssuer();
        String issuersCsv = issuer.issuerUri() + "=brandx," + issuer2.issuerUri() + "=brandy";
        DomainRegistry registry = new DomainRegistry(issuer.issuerUri(), issuersCsv);
        TenancyResourceServerConfig tenancy =
                new TenancyResourceServerConfig(registry, "", "", false, 600000L);
        ReactiveAuthenticationManagerResolver<ServerWebExchange> resolver =
                systems.snapdragon.commons.config.TenancyResolvers.tenantResolver(tenancy);
        client = sliceClient(registry, provider(resolver), new ProbeController());
    }

    @AfterEach
    void tearDown() {
        issuer.close();
        issuer2.close();
    }

    private WebTestClient client() {
        return client;
    }

    @Test
    void hardenedHeaders_present_onPublicProbeResponse() {
        // /actuator/health is anonymously allowed (200) — the headers ride on a real
        // response that completes through the chain.
        client().get().uri("/actuator/health").exchange()
                .expectStatus().isOk()
                .expectHeader().valueEquals(
                        "Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
                .expectHeader().valueEquals("Referrer-Policy", "no-referrer")
                // Spring secure DEFAULTS — kept, never disabled.
                .expectHeader().valueEquals("X-Content-Type-Options", "nosniff")
                .expectHeader().valueEquals("X-Frame-Options", "DENY");
    }

    @Test
    void cacheControl_default_present() {
        client().get().uri("/actuator/health").exchange()
                .expectStatus().isOk()
                .expectHeader().exists(HttpHeaders.CACHE_CONTROL);
    }

    @Test
    void hsts_deliberatelyAbsent_notTheTlsFrontDoor() {
        // HSTS lives ONLY at the gateway TLS edge; a non-edge JSON BFF must not assert
        // it (meaningless over plaintext intra-mesh).
        client().get().uri("/actuator/health").exchange()
                .expectStatus().isOk()
                .expectHeader().doesNotExist("Strict-Transport-Security");
    }

    @Test
    void unauthenticatedGatedRequest_still401s_andCarriesHardenedHeaders() {
        // The header block is ADDITIVE: it never weakens the anyExchange().authenticated()
        // deny-by-default floor — an anonymous call to a gated path still 401s, and the
        // 401 response still carries the hardened CSP.
        client().get().uri("/bff/user/_probe").exchange()
                .expectStatus().isUnauthorized()
                .expectHeader().valueEquals(
                        "Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
                .expectHeader().valueEquals("X-Content-Type-Options", "nosniff");
    }

    @Test
    void cspValue_isExactly_theLockedDownApiPolicy() {
        // Pin the exact directive string so a future loosening (e.g. adding script-src
        // 'unsafe-inline') is caught by this regression guard.
        String csp = client().get().uri("/actuator/health").exchange()
                .expectStatus().isOk()
                .returnResult(String.class)
                .getResponseHeaders().getFirst("Content-Security-Policy");
        assertThat(csp).isEqualTo("default-src 'none'; frame-ancestors 'none'");
    }

    @RestController
    static class ProbeController {
        @RequestMapping({"/actuator/health", "/bff/user/_probe"})
        Mono<String> ok() {
            return Mono.just("ok");
        }
    }
}
