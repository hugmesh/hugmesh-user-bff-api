package net.hugmesh.userbff.config;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import net.hugmesh.commons.config.TenancyResolvers;
import net.hugmesh.commons.config.TenancyResourceServerConfig;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.userbff.auth.AdminBffInternalClient;
import net.hugmesh.userbff.auth.AdminBffInternalClient.AccountView;
import net.hugmesh.userbff.testsupport.TestIssuer;

import java.util.List;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * END-TO-END slice for {@link BffSessionAuthenticationWebFilter} INSTALLED ALONGSIDE
 * the real {@link SecurityConfig#filterChain}, via {@link
 * SecuritySliceSupport#sliceClientWithBffSessionAuth}. Complements the pure-unit
 * {@link BffSessionAuthenticationWebFilterTest} (which exercises the filter in
 * isolation with a hand-rolled {@code WebFilterChain}) by proving the bridge actually
 * satisfies {@code SecurityConfig}'s real {@code authorizeExchange} rules — i.e. that a
 * {@code bff_session} cookie alone (NO JWT) now reaches {@code /bff/user/**} and
 * {@code /bff/me}, which {@code SecurityConfigPathGateSliceTest}'s LIVE REPRODUCTION
 * (see PR description) proved was 401 BEFORE this filter existed.
 *
 * <p>{@code /bff/me} is deliberately included in the probe mapping — {@code
 * SecurityConfigPathGateSliceTest}'s {@code ProbeController} never mapped it, which is
 * exactly why the pre-existing test suite never caught the {@code /bff/me} instance of
 * this gap (see PR description "Live reproduction #2").
 */
class BffSessionAuthenticationSliceTest extends SecuritySliceSupport {

    private TestIssuer issuer;
    private TestIssuer issuer2;

    @BeforeEach
    void setUp() {
        issuer = new TestIssuer();
        issuer2 = new TestIssuer();
    }

    @AfterEach
    void tearDown() {
        issuer.close();
        issuer2.close();
    }

    private WebTestClient clientWith(AdminBffInternalClient adminBffClient) {
        String issuersCsv = issuer.issuerUri() + "=brandx," + issuer2.issuerUri() + "=brandy";
        DomainRegistry registry = new DomainRegistry(issuer.issuerUri(), issuersCsv);
        TenancyResourceServerConfig tenancy = new TenancyResourceServerConfig(registry, "", "", false, 600000L);
        ReactiveAuthenticationManagerResolver<ServerWebExchange> resolver =
                TenancyResolvers.tenantResolver(tenancy);
        return sliceClientWithBffSessionAuth(registry, provider(resolver), provider(adminBffClient), new ProbeController());
    }

    private static AdminBffInternalClient enabledClientReturning(String token, AccountView view) {
        AdminBffInternalClient client = mock(AdminBffInternalClient.class);
        when(client.enabled()).thenReturn(true);
        when(client.resolveSession(token)).thenReturn(Mono.just(new AdminBffInternalClient.SessionResolution(view, "active", false)));
        return client;
    }

    // ── the gap this filter closes: bff_session cookie alone now authenticates ──

    @Test
    void bffSessionCookie_noJwt_reachesUserSurface() {
        AccountView view = new AccountView("acct-1", "native", "someone", true, List.of("user"), "lp");
        AdminBffInternalClient client = enabledClientReturning("bff_validtoken", view);

        clientWith(client).get().uri("/bff/user/_probe")
                .cookie("bff_session", "bff_validtoken")
                .exchange()
                .expectStatus().isOk();
    }

    // ── BUG 1: the Authorization-HEADER carrier, through the REAL chain ─────────

    @Test
    void bffSessionHeader_noCookie_reachesUserSurface() {
        // The exact gap that shipped in the merged PR #107 code: WITHOUT
        // SecurityConfig's bearerTokenConverter skip-guard, Spring's stock
        // bearer-token extraction grabs this SAME "Authorization: Bearer bff_..."
        // header, hands the opaque token to the JWT decoder ("Invalid JWT
        // serialization: Missing dot delimiter(s)"), and the resource server's own
        // failure handler commits a 401 DIRECTLY — overriding the SecurityContext
        // BffSessionAuthenticationWebFilter already populated. This test combination
        // (header carrier + the REAL SecurityConfig.filterChain + a protected route)
        // is exactly what let the bug ship: bffSessionCookie_noJwt_reachesUserSurface
        // above only ever exercised the cookie carrier, which the stock bearer-token
        // converter never even looks at (no Authorization header present), so it
        // could never have caught this.
        AccountView view = new AccountView("acct-header-1", "native", "someone-h", true, List.of("user"), "lp");
        AdminBffInternalClient client = enabledClientReturning("bff_headertoken", view);

        clientWith(client).get().uri("/bff/user/_probe")
                .header("Authorization", "Bearer bff_headertoken")
                .exchange()
                .expectStatus().isOk();

        org.mockito.Mockito.verify(client).resolveSession("bff_headertoken");
    }

    @Test
    void bffSessionHeader_noCookie_reachesMe() {
        // /bff/me specifically, mirroring bffSessionCookie_noJwt_reachesMe's "Live
        // reproduction #2" — the header carrier is SsoAuthController's OWN documented
        // native-login calling convention too (not just the cookie), so it must also
        // reach /bff/me through the real chain.
        AccountView view = new AccountView("acct-header-2", "native", "someone-h2", true, List.of("user"), "lp");
        AdminBffInternalClient client = enabledClientReturning("bff_headertoken2", view);

        clientWith(client).get().uri("/bff/me")
                .header("Authorization", "Bearer bff_headertoken2")
                .exchange()
                .expectStatus().isOk();
    }

    @Test
    void bffSessionHeader_unknownOrExpired_is401_notMisdecodedAsJwt() {
        // Proves the skip-guard's Mono.empty() branch (not just "no converter ran at
        // all") — an invalid/expired bff_ token via the header must still reach the
        // filter's OWN 401 (unauthenticated pass-through -> .authenticated() 401), not
        // Spring's JWT-decode failure 401 (same status code, but for the WRONG reason
        // — the distinction matters because a decode-failure 401 would mean the guard
        // never engaged, i.e. this test would pass even with Bug 1 unfixed. The
        // verify() call below is what actually distinguishes the two: the JWT decoder
        // path never calls admin-bff at all).
        AdminBffInternalClient client = mock(AdminBffInternalClient.class);
        when(client.enabled()).thenReturn(true);
        when(client.resolveSession("bff_badheader"))
                .thenReturn(Mono.error(new ResponseStatusException(HttpStatus.UNAUTHORIZED, "unknown or expired session")));

        clientWith(client).get().uri("/bff/user/_probe")
                .header("Authorization", "Bearer bff_badheader")
                .exchange()
                .expectStatus().isUnauthorized();

        org.mockito.Mockito.verify(client).resolveSession("bff_badheader");
    }

    @Test
    void bffSessionCookie_noJwt_reachesMe() {
        // Live reproduction #2 from the PR description: /bff/me with ONLY a bff_session
        // cookie (no Authorization header) — SsoAuthController.me()'s own documented
        // native-login calling convention — was 401'd BEFORE the controller was ever
        // reached. This proves the bridge filter now lets it through to the handler.
        AccountView view = new AccountView("acct-2", "native", "someone2", true, List.of("user"), "lp");
        AdminBffInternalClient client = enabledClientReturning("bff_validtoken2", view);

        clientWith(client).get().uri("/bff/me")
                .cookie("bff_session", "bff_validtoken2")
                .exchange()
                .expectStatus().isOk();
    }

    // ── unknown/expired session → clean 401 (not a 500, not silently authenticated) ──

    @Test
    void bffSessionCookie_unknownOrExpired_is401() {
        AdminBffInternalClient client = mock(AdminBffInternalClient.class);
        when(client.enabled()).thenReturn(true);
        when(client.resolveSession("bff_expired"))
                .thenReturn(Mono.error(new ResponseStatusException(HttpStatus.UNAUTHORIZED, "unknown or expired session")));

        clientWith(client).get().uri("/bff/user/_probe")
                .cookie("bff_session", "bff_expired")
                .exchange()
                .expectStatus().isUnauthorized();
    }

    // ── admin-bff outage while a bff_ token is presented → fail-closed 503 ──────

    @Test
    void bffSessionCookie_adminBffOutage_is503() {
        AdminBffInternalClient client = mock(AdminBffInternalClient.class);
        when(client.enabled()).thenReturn(true);
        when(client.resolveSession("bff_sometoken")).thenReturn(Mono.error(
                WebClientResponseException.create(503, "Service Unavailable",
                        org.springframework.http.HttpHeaders.EMPTY, new byte[0], null)));

        clientWith(client).get().uri("/bff/user/_probe")
                .cookie("bff_session", "bff_sometoken")
                .exchange()
                .expectStatus().isEqualTo(HttpStatus.SERVICE_UNAVAILABLE);
    }

    // ── ROLE_SERVICE gate still holds for a human bff_ session (IDOR guard) ─────

    @Test
    void bffSessionCookie_humanUser_stillForbiddenOnInternalSurface() {
        // A human caller authenticated purely via a native-login bff_ session must be
        // JUST as unable to reach /bff/user/internal/** as a human JWT caller already
        // is (SecurityConfigPathGateSliceTest.internalSurface_plainUser_isForbidden) —
        // the bridge filter must never grant ROLE_SERVICE to an ordinary account.
        AccountView view = new AccountView("acct-3", "native", "someone3", true, List.of("user", "admin"), "lp");
        AdminBffInternalClient client = enabledClientReturning("bff_humantoken", view);

        clientWith(client).get().uri("/bff/user/internal/notifications/deliver")
                .cookie("bff_session", "bff_humantoken")
                .exchange()
                .expectStatus().isForbidden();
    }

    // ── no bff_ token at all: the real Casdoor JWT path is untouched ────────────

    @Test
    void jwtBearer_stillWorks_whenBffFilterIsAlsoInstalled() {
        AdminBffInternalClient client = mock(AdminBffInternalClient.class);
        when(client.enabled()).thenReturn(true);

        String token = issuer.mint("p-user", List.of("user"));
        clientWith(client).get().uri("/bff/user/_probe")
                .header("Authorization", "Bearer " + token)
                .exchange()
                .expectStatus().isOk();
        // The bridge filter must never even attempt admin-bff resolution for a JWT-only
        // request — see BffSessionAuthenticationWebFilterTest's equivalent unit proof.
    }

    // ── anonymous (no token anywhere) still 401s exactly as before ──────────────

    @Test
    void anonymous_stillUnauthorized_whenBffFilterIsAlsoInstalled() {
        AdminBffInternalClient client = mock(AdminBffInternalClient.class);
        when(client.enabled()).thenReturn(true);

        clientWith(client).get().uri("/bff/user/_probe")
                .exchange()
                .expectStatus().isUnauthorized();
    }

    /** Mirrors {@code SecurityConfigPathGateSliceTest.ProbeController}, plus {@code
     *  /bff/me} (deliberately absent there — see the class doc "Live reproduction #2"). */
    @RestController
    static class ProbeController {
        @RequestMapping({
                "/bff/user/internal/notifications/deliver",
                "/bff/user/_probe",
                "/bff/me",
        })
        Mono<String> ok() {
            return Mono.just("ok");
        }
    }
}
