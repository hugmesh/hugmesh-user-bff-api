package systems.snapdragon.userbff.preference;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.WebFluxTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;
import systems.snapdragon.userbff.config.SecurityConfig;
import systems.snapdragon.userbff.security.PrincipalDomain;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;

/**
 * METHOD-LEVEL {@code @PreAuthorize("hasRole('USER')")} gate test for
 * {@link HomeGuideController}, driven through {@link WebTestClient} with synthetic
 * authentications. Mirrors the repo's existing {@code ConnectedClientsControllerGateTest}
 * pattern (the way this codebase proves a {@code @PreAuthorize} controller gate:
 * {@code @WebFluxTest} + {@code @Import(SecurityConfig.class)} so
 * {@code @EnableReactiveMethodSecurity} actually wires the method-security
 * interceptor — a pure WebTestClient filter-chain slice does NOT enforce
 * {@code @PreAuthorize}).
 *
 * <p>This controller is the path-gate's specific gap: its class-level
 * {@code @PreAuthorize("hasRole('USER')")} is a defence-in-depth layer ABOVE the
 * {@code /bff/user/**} authorizeExchange floor, and was not previously covered by a
 * boundary test. We assert:
 * <ul>
 *   <li><b>ANONYMOUS DENY (401)</b> — no credentials → 401 at the controller boundary
 *       (the authorizeExchange floor); the service is never invoked;</li>
 *   <li><b>NON-USER DENY (403)</b> — an authenticated principal WITHOUT {@code ROLE_USER}
 *       (e.g. a token carrying only some other authority) → 403 by the
 *       {@code hasRole('USER')} method gate; the service is never invoked;</li>
 *   <li><b>USER ALLOW (200)</b> — {@code ROLE_USER} reaches the handler + service.</li>
 * </ul>
 *
 * <p>Categories per the comprehensive test standard: ANONYMOUS/NON-USER are
 * CROSS-USER DENY at the controller boundary; the ROLE_USER case is USER-SITUATIONAL
 * ALLOW.
 */
@WebFluxTest(controllers = HomeGuideController.class)
@Import(SecurityConfig.class)
class HomeGuideControllerGateTest {

    @Autowired WebTestClient client;

    @MockitoBean ReactiveJwtDecoder jwtDecoder;
    @MockitoBean HomeGuideService guides;
    @MockitoBean PrincipalDomain principalDomain;

    private static Collection<GrantedAuthority> authorities(String... names) {
        List<GrantedAuthority> out = new ArrayList<>();
        for (String n : names) out.add(new SimpleGrantedAuthority(n));
        return out;
    }

    // ── ANONYMOUS DENY — 401 at the controller boundary, service never called ──

    @Test
    void status_anonymous_isUnauthorized_serviceNeverCalled() {
        client.get().uri("/bff/user/home-guide")
                .exchange()
                .expectStatus().isUnauthorized();
        verify(guides, never()).isDismissed(anyString(), anyString(), any());
    }

    @Test
    void dismiss_anonymous_isUnauthorized_serviceNeverCalled() {
        client.post().uri("/bff/user/home-guide/dismiss")
                .exchange()
                .expectStatus().isUnauthorized();
        verify(guides, never()).dismiss(anyString(), anyString(), any());
    }

    // ── NON-USER DENY — hasRole('USER') 403, service never called ──────────────

    @Test
    void status_withoutUserRole_isForbidden_serviceNeverCalled() {
        // An authenticated principal that carries SOME authority but NOT ROLE_USER is
        // rejected by the class-level @PreAuthorize("hasRole('USER')") — 403, never
        // 200, and the service is never invoked. (DOMAIN_brandx is a non-role
        // authority; it can never satisfy hasRole('USER').)
        client.mutateWith(mockJwt().jwt(j -> j.subject("nobody"))
                        .authorities(authorities("DOMAIN_brandx")))
                .get().uri("/bff/user/home-guide")
                .exchange()
                .expectStatus().isForbidden();
        verify(guides, never()).isDismissed(anyString(), anyString(), any());
    }

    @Test
    void dismiss_withoutUserRole_isForbidden_serviceNeverCalled() {
        client.mutateWith(mockJwt().jwt(j -> j.subject("nobody"))
                        .authorities(authorities("DOMAIN_brandx")))
                .post().uri("/bff/user/home-guide/dismiss")
                .exchange()
                .expectStatus().isForbidden();
        verify(guides, never()).dismiss(anyString(), anyString(), any());
    }

    // ── USER ALLOW — ROLE_USER reaches the handler + service ──────────────────

    @Test
    void status_withUserRole_reachesService() {
        when(principalDomain.forScope(any(Jwt.class))).thenReturn("brandx");
        when(guides.isDismissed(anyString(), anyString(), any())).thenReturn(Mono.just(false));
        client.mutateWith(mockJwt().jwt(j -> j.subject("alice"))
                        .authorities(authorities("ROLE_USER", "DOMAIN_brandx")))
                .get().uri("/bff/user/home-guide")
                .exchange()
                .expectStatus().isOk();
        verify(guides).isDismissed(anyString(), anyString(), any());
    }

    @Test
    void dismiss_withUserRole_reachesService() {
        when(principalDomain.forScope(any(Jwt.class))).thenReturn("brandx");
        when(guides.dismiss(anyString(), anyString(), any())).thenReturn(Mono.empty());
        client.mutateWith(mockJwt().jwt(j -> j.subject("alice"))
                        .authorities(authorities("ROLE_USER", "DOMAIN_brandx")))
                .post().uri("/bff/user/home-guide/dismiss")
                .exchange()
                .expectStatus().isOk();
        verify(guides).dismiss(anyString(), anyString(), any());
    }
}
