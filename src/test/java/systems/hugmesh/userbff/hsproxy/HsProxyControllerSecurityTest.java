package systems.hugmesh.userbff.hsproxy;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.boot.webflux.test.autoconfigure.WebFluxTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.reactive.function.client.WebClient;
import systems.hugmesh.userbff.auth.AdminBffInternalClient;
import systems.hugmesh.userbff.auth.CanonicalIdentityResolver;
import systems.hugmesh.userbff.config.SecurityConfig;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * Security + SHIPS-DARK surface tests for the D6 proxy controllers via
 * {@link WebTestClient} with synthetic authentications. The custody/broker are mocked
 * (no live homeserver). Asserts:
 * <ul>
 *   <li>anonymous → 401 on both surfaces (the ROLE_USER floor + @PreAuthorize);</li>
 *   <li>a ROLE_USER without ROLE_MATRIX/ROLE_MASTODON → 403 (the per-platform gate);</li>
 *   <li><b>ships dark</b>: with the matching role but {@code app.hs-token.enabled=false}
 *       the endpoint 503s and the custody store is NEVER touched (no token read);</li>
 *   <li>cross-surface: a MATRIX-only role is 403 on the Mastodon surface (no leakage).</li>
 * </ul>
 *
 * <p>This test pins the DARK posture EXPLICITLY via {@code @TestPropertySource}
 * ({@code app.hs-token.enabled=false}) — the application.yml default is now {@code true}
 * (the proxy is live so the browser holds no homeserver token), so the dark-behaviour
 * assertions must override it locally rather than rely on the shipped default.
 */
@WebFluxTest(controllers = {MatrixProxyController.class, MastodonProxyController.class})
@Import({SecurityConfig.class, CanonicalIdentityResolver.class, HsProxyControllerSecurityTest.StubClients.class})
@TestPropertySource(properties = "app.hs-token.enabled=false")
class HsProxyControllerSecurityTest {

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
    @MockitoBean HsTokenCustody custody;
    @MockitoBean ServiceTokenBroker broker;
    // Gap-1 close: the controllers now take AdminBffInternalClient as a constructor dep
    // (the localpart(Jwt) fallback's real internal admin-bff lookup). Never touched in
    // these dark-path tests (the 503 short-circuits before localpart(jwt) is ever called).
    @MockitoBean AdminBffInternalClient adminBff;

    /** The two qualified proxy WebClients the controllers inject (never called in the
     *  dark path — the 503 short-circuits before any upstream use). */
    @TestConfiguration
    static class StubClients {
        @Bean("matrixProxyWebClient")
        WebClient matrixProxyWebClient() { return WebClient.builder().build(); }

        @Bean("mastodonProxyWebClient")
        WebClient mastodonProxyWebClient() { return WebClient.builder().build(); }
    }

    private static Collection<GrantedAuthority> authorities(String... names) {
        List<GrantedAuthority> out = new ArrayList<>();
        for (String n : names) {
            out.add(new SimpleGrantedAuthority(n));
        }
        return out;
    }

    @Test
    void matrix_anonymous_isUnauthorized() {
        client.get().uri("/bff/user/matrix/_matrix/client/v3/sync")
                .exchange()
                .expectStatus().isUnauthorized();
    }

    @Test
    void mastodon_anonymous_isUnauthorized() {
        client.get().uri("/bff/user/mastodon/api/v1/timelines/home")
                .exchange()
                .expectStatus().isUnauthorized();
    }

    @Test
    void matrix_userWithoutMatrixRole_isForbidden() {
        client.mutateWith(mockJwt().jwt(j -> j.subject("alice")).authorities(authorities("ROLE_USER")))
                .get().uri("/bff/user/matrix/_matrix/client/v3/sync")
                .exchange()
                .expectStatus().isForbidden();
    }

    @Test
    void matrix_withRole_butFeatureDark_is503_andCustodyNeverTouched() {
        client.mutateWith(mockJwt().jwt(j -> j.subject("alice").claim("preferred_username", "alice"))
                        .authorities(authorities("ROLE_USER", "ROLE_MATRIX")))
                .get().uri("/bff/user/matrix/_matrix/client/v3/sync")
                .exchange()
                .expectStatus().isEqualTo(503);
        // SHIPS-DARK: the dark 503 short-circuits before any custody read / mint.
        verify(custody, never()).loadAccessToken(org.mockito.ArgumentMatchers.anyString(),
                org.mockito.ArgumentMatchers.anyString());
        verify(broker, never()).mintMatrix(org.mockito.ArgumentMatchers.anyString(),
                org.mockito.ArgumentMatchers.anyString());
    }

    @Test
    void mastodon_withRole_butFeatureDark_is503_andCustodyNeverTouched() {
        client.mutateWith(mockJwt().jwt(j -> j.subject("alice").claim("preferred_username", "alice"))
                        .authorities(authorities("ROLE_USER", "ROLE_MASTODON")))
                .get().uri("/bff/user/mastodon/api/v1/streaming/user")
                .exchange()
                .expectStatus().isEqualTo(503);
        verify(custody, never()).loadAccessToken(org.mockito.ArgumentMatchers.anyString(),
                org.mockito.ArgumentMatchers.anyString());
        verify(broker, never()).mintMastodon(org.mockito.ArgumentMatchers.anyString(),
                org.mockito.ArgumentMatchers.anyString());
    }

    @Test
    void matrixRole_cannotReachMastodonSurface() {
        client.mutateWith(mockJwt().jwt(j -> j.subject("alice")).authorities(authorities("ROLE_USER", "ROLE_MATRIX")))
                .get().uri("/bff/user/mastodon/api/v1/timelines/home")
                .exchange()
                .expectStatus().isForbidden();
    }
}
