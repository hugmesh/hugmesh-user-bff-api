package systems.hugmesh.userbff.prefstore;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.boot.webflux.test.autoconfigure.WebFluxTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;
import systems.hugmesh.userbff.config.SecurityConfig;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * Slice test for {@link UserPreferencesController} via {@link WebTestClient}, importing
 * the real {@link SecurityConfig} so the {@code /bff/user/**} authenticated floor + the
 * {@code @PreAuthorize("hasRole('USER')")} method gate are exercised; the
 * {@link UserPreferencesService} is mocked. Delineated per the test standard:
 *
 * <ul>
 *   <li><b>USER-SITUATIONAL</b> — a ROLE_USER reads GET and upserts via PUT; the body
 *       is validated (a bad/blank key is a 400 before the service is touched).</li>
 *   <li><b>CROSS-USER</b> — the owner is taken from the JWT SUBJECT (never a body
 *       field), so a caller can only ever read/write their OWN prefs; anonymous is 401
 *       on both verbs (the service is never reached).</li>
 * </ul>
 */
@WebFluxTest(controllers = UserPreferencesController.class)
@Import(SecurityConfig.class)
@EnableReactiveMethodSecurity
class UserPreferencesControllerTest {

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
    @MockitoBean UserPreferencesService service;

    private static Collection<GrantedAuthority> authorities(String... names) {
        List<GrantedAuthority> out = new ArrayList<>();
        for (String n : names) out.add(new SimpleGrantedAuthority(n));
        return out;
    }

    // ── USER-SITUATIONAL ──────────────────────────────────────────────────────
    @Nested
    class UserSituational {
        @Test
        void get_authenticatedUser_returnsResolvedView() {
            when(service.get(eq("alice"), any()))
                    .thenReturn(Mono.just(Map.of("media.poison.default", "medium")));

            client.mutateWith(mockJwt().jwt(j -> j.subject("alice")).authorities(authorities("ROLE_USER")))
                    .get().uri("/bff/user/preferences")
                    .exchange()
                    .expectStatus().isOk()
                    .expectBody()
                    .jsonPath("$['media.poison.default']").isEqualTo("medium");

            verify(service).get(eq("alice"), any());
        }

        @Test
        void put_authenticatedUser_upsertsAndReturnsResolvedView() {
            when(service.put(eq("alice"), eq("media.poison.default"), eq("high"), any()))
                    .thenReturn(Mono.just(Map.of("media.poison.default", "high")));

            client.mutateWith(mockJwt().jwt(j -> j.subject("alice")).authorities(authorities("ROLE_USER")))
                    .put().uri("/bff/user/preferences")
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(Map.of("key", "media.poison.default", "value", "high"))
                    .exchange()
                    .expectStatus().isOk()
                    .expectBody()
                    .jsonPath("$['media.poison.default']").isEqualTo("high");

            verify(service).put(eq("alice"), eq("media.poison.default"), eq("high"), any());
        }

        @Test
        void put_blankKey_isBadRequest_serviceNotReached() {
            client.mutateWith(mockJwt().jwt(j -> j.subject("alice")).authorities(authorities("ROLE_USER")))
                    .put().uri("/bff/user/preferences")
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(Map.of("key", "", "value", "high"))
                    .exchange()
                    .expectStatus().isBadRequest();

            verify(service, never()).put(any(), any(), any(), any());
        }

        @Test
        void put_illegalKeyToken_isBadRequest_serviceNotReached() {
            client.mutateWith(mockJwt().jwt(j -> j.subject("alice")).authorities(authorities("ROLE_USER")))
                    .put().uri("/bff/user/preferences")
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(Map.of("key", "bad key!", "value", "high"))
                    .exchange()
                    .expectStatus().isBadRequest();

            verify(service, never()).put(any(), any(), any(), any());
        }
    }

    // ── CROSS-USER ────────────────────────────────────────────────────────────
    @Nested
    class CrossUser {
        @Test
        void get_ownerIsJwtSubject_notARequestField() {
            // even if a different name appears anywhere, the owner is the JWT subject.
            when(service.get(eq("bob"), any())).thenReturn(Mono.just(Map.of()));

            client.mutateWith(mockJwt().jwt(j -> j.subject("bob")).authorities(authorities("ROLE_USER")))
                    .get().uri("/bff/user/preferences")
                    .exchange()
                    .expectStatus().isOk();

            verify(service).get(eq("bob"), any());
            verify(service, never()).get(eq("alice"), any());
        }

        @Test
        void get_anonymous_isUnauthorized_serviceNotReached() {
            client.get().uri("/bff/user/preferences").exchange().expectStatus().isUnauthorized();
            verify(service, never()).get(any(), any());
        }

        @Test
        void put_anonymous_isUnauthorized_serviceNotReached() {
            client.put().uri("/bff/user/preferences")
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(Map.of("key", "media.poison.default", "value", "high"))
                    .exchange()
                    .expectStatus().isUnauthorized();
            verify(service, never()).put(any(), any(), any(), any());
        }
    }
}
