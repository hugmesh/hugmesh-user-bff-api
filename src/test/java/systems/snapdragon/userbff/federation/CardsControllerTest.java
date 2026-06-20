package systems.snapdragon.userbff.federation;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.boot.webflux.test.autoconfigure.WebFluxTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;
import systems.snapdragon.userbff.config.SecurityConfig;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * Slice test for the {@link CardsController} read-body + delete proxy routes
 * driven via {@link WebTestClient}. Imports the real {@link SecurityConfig} so the
 * {@code /bff/user/**} ROLE_USER floor + the {@code @PreAuthorize("hasRole('USER')")}
 * method gate are exercised; the upstream {@link FederationApiClient} is mocked, so
 * this asserts the controller delegates to the OWNER-scoped client call (the
 * forwarded-JWT owner-enforcement itself is covered by FederationApiClientTest /
 * FederationWebClientConfigTest). Proves:
 * <ul>
 *   <li>anonymous is rejected (no token -> 401) for both routes;</li>
 *   <li>an authenticated ROLE_USER reaches the routes and the controller calls
 *       {@code federation.readBody(slug)} / {@code federation.delete(slug)};</li>
 *   <li>delete returns 204 No Content.</li>
 * </ul>
 */
@WebFluxTest(controllers = CardsController.class)
@Import(SecurityConfig.class)
@EnableReactiveMethodSecurity
class CardsControllerTest {

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
    @MockitoBean FederationApiClient federation;

    private static Collection<GrantedAuthority> authorities(String... names) {
        List<GrantedAuthority> out = new ArrayList<>();
        for (String n : names) out.add(new SimpleGrantedAuthority(n));
        return out;
    }

    // ---------- read-body ----------

    @Test
    void body_anonymous_isUnauthorized() {
        client.get().uri("/bff/user/cards/my-card/body").exchange().expectStatus().isUnauthorized();
        verify(federation, never()).readBody(eq("my-card"));
    }

    @Test
    void body_authenticatedUser_delegatesToOwnerScopedReadBody() {
        when(federation.readBody(eq("my-card")))
                .thenReturn(Mono.just("<h1>my card</h1>".getBytes()));

        client.mutateWith(mockJwt().authorities(authorities("ROLE_USER")))
                .get().uri("/bff/user/cards/my-card/body")
                .exchange()
                .expectStatus().isOk()
                .expectBody(byte[].class).isEqualTo("<h1>my card</h1>".getBytes());

        verify(federation).readBody("my-card");
    }

    // ---------- delete ----------

    @Test
    void delete_anonymous_isUnauthorized() {
        client.delete().uri("/bff/user/cards/my-card").exchange().expectStatus().isUnauthorized();
        verify(federation, never()).delete(eq("my-card"));
    }

    @Test
    void delete_authenticatedUser_delegatesAndReturns204() {
        when(federation.delete(eq("my-card"))).thenReturn(Mono.empty());

        client.mutateWith(mockJwt().authorities(authorities("ROLE_USER")))
                .delete().uri("/bff/user/cards/my-card")
                .exchange()
                .expectStatus().isNoContent();

        verify(federation).delete("my-card");
    }
}
