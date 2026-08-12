package net.hugmesh.userbff.notification;

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
import net.hugmesh.userbff.config.SecurityConfig;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * Slice test for {@link NotificationPreferenceController} via {@link WebTestClient},
 * importing the real {@link SecurityConfig} so the {@code /bff/user/**} authenticated
 * floor + the {@code @PreAuthorize("hasRole('USER')")} method gate are exercised; the
 * {@link NotificationPreferenceService} is mocked. Delineated per the test standard:
 *
 * <ul>
 *   <li><b>USER-SITUATIONAL</b> — a ROLE_USER reads GET and upserts via PUT; the body is
 *       validated (a bad/blank category or a missing enabled is a 400 before the service
 *       is touched).</li>
 *   <li><b>CROSS-USER</b> — the owner is taken from the JWT SUBJECT (never a body field),
 *       so a caller can only ever read/write their OWN prefs; FAIL-CLOSED: a non-JWT /
 *       anonymous request is 401 on both verbs (the service is never reached).</li>
 * </ul>
 */
@WebFluxTest(controllers = NotificationPreferenceController.class)
@Import(SecurityConfig.class)
@EnableReactiveMethodSecurity
class NotificationPreferenceControllerTest {

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
    @MockitoBean NotificationPreferenceService service;

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
                    .thenReturn(Mono.just(Map.of("account-restriction", true, "role-change", false)));

            client.mutateWith(mockJwt().jwt(j -> j.subject("alice")).authorities(authorities("ROLE_USER")))
                    .get().uri("/bff/user/notification-preferences")
                    .exchange()
                    .expectStatus().isOk()
                    .expectBody()
                    .jsonPath("$['account-restriction']").isEqualTo(true)
                    .jsonPath("$['role-change']").isEqualTo(false);

            verify(service).get(eq("alice"), any());
        }

        @Test
        void put_authenticatedUser_upsertsAndReturnsResolvedView() {
            when(service.put(eq("alice"), eq("role-change"), eq(false), any()))
                    .thenReturn(Mono.just(Map.of("role-change", false)));

            client.mutateWith(mockJwt().jwt(j -> j.subject("alice")).authorities(authorities("ROLE_USER")))
                    .put().uri("/bff/user/notification-preferences")
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(Map.of("category", "role-change", "enabled", false))
                    .exchange()
                    .expectStatus().isOk()
                    .expectBody()
                    .jsonPath("$['role-change']").isEqualTo(false);

            verify(service).put(eq("alice"), eq("role-change"), eq(false), any());
        }

        @Test
        void put_blankCategory_isBadRequest_serviceNotReached() {
            client.mutateWith(mockJwt().jwt(j -> j.subject("alice")).authorities(authorities("ROLE_USER")))
                    .put().uri("/bff/user/notification-preferences")
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(Map.of("category", "", "enabled", true))
                    .exchange()
                    .expectStatus().isBadRequest();

            verify(service, never()).put(anyString(), anyString(), anyBoolean(), any());
        }

        @Test
        void put_illegalCategoryToken_isBadRequest_serviceNotReached() {
            client.mutateWith(mockJwt().jwt(j -> j.subject("alice")).authorities(authorities("ROLE_USER")))
                    .put().uri("/bff/user/notification-preferences")
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(Map.of("category", "Bad Category!", "enabled", true))
                    .exchange()
                    .expectStatus().isBadRequest();

            verify(service, never()).put(anyString(), anyString(), anyBoolean(), any());
        }

        @Test
        void put_missingEnabled_isBadRequest_serviceNotReached() {
            client.mutateWith(mockJwt().jwt(j -> j.subject("alice")).authorities(authorities("ROLE_USER")))
                    .put().uri("/bff/user/notification-preferences")
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(Map.of("category", "role-change"))
                    .exchange()
                    .expectStatus().isBadRequest();

            verify(service, never()).put(anyString(), anyString(), anyBoolean(), any());
        }
    }

    // ── CROSS-USER ────────────────────────────────────────────────────────────
    @Nested
    class CrossUser {
        @Test
        void get_ownerIsJwtSubject_notARequestField() {
            when(service.get(eq("bob"), any())).thenReturn(Mono.just(Map.of()));

            client.mutateWith(mockJwt().jwt(j -> j.subject("bob")).authorities(authorities("ROLE_USER")))
                    .get().uri("/bff/user/notification-preferences")
                    .exchange()
                    .expectStatus().isOk();

            verify(service).get(eq("bob"), any());
            verify(service, never()).get(eq("alice"), any());
        }

        @Test
        void get_anonymous_isUnauthorized_serviceNotReached() {
            client.get().uri("/bff/user/notification-preferences")
                    .exchange().expectStatus().isUnauthorized();
            verify(service, never()).get(any(), any());
        }

        @Test
        void put_anonymous_isUnauthorized_serviceNotReached() {
            client.put().uri("/bff/user/notification-preferences")
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(Map.of("category", "role-change", "enabled", false))
                    .exchange()
                    .expectStatus().isUnauthorized();
            verify(service, never()).put(anyString(), anyString(), anyBoolean(), any());
        }
    }
}
