package systems.snapdragon.userbff.notification;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.WebFluxTest;
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

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;

/**
 * Slice test for {@link UserNotificationController} via {@link WebTestClient}, importing
 * the real {@link SecurityConfig} so the {@code /bff/user/**} authenticated floor + the
 * {@code @PreAuthorize("hasRole('USER')")} method gate are exercised; the
 * {@link UserNotificationService} is mocked. Delineated per the test standard:
 *
 * <ul>
 *   <li><b>USER-SITUATIONAL</b> — a ROLE_USER lists GET and marks a notification read;
 *       the {id} path is UUID-validated (a non-UUID is a 400 before the service is
 *       touched); the {@code limit} param is bounded.</li>
 *   <li><b>CROSS-USER</b> — the owner is taken from the JWT SUBJECT (never a path/body
 *       field); FAIL-CLOSED: a non-JWT / anonymous request is 401 on both verbs (the
 *       service is never reached).</li>
 * </ul>
 */
@WebFluxTest(controllers = UserNotificationController.class)
@Import(SecurityConfig.class)
@EnableReactiveMethodSecurity
class UserNotificationControllerTest {

    @Autowired WebTestClient client;

    @MockitoBean ReactiveJwtDecoder jwtDecoder;
    @MockitoBean UserNotificationService service;

    private static final String UUID1 = "11111111-1111-1111-1111-111111111111";

    private static Collection<GrantedAuthority> authorities(String... names) {
        List<GrantedAuthority> out = new ArrayList<>();
        for (String n : names) out.add(new SimpleGrantedAuthority(n));
        return out;
    }

    // ── USER-SITUATIONAL ──────────────────────────────────────────────────────
    @Nested
    class UserSituational {
        @Test
        void list_authenticatedUser_returnsOwnNotifications() {
            when(service.list(eq("alice"), any(), eq(50)))
                    .thenReturn(Mono.just(List.of()));

            client.mutateWith(mockJwt().jwt(j -> j.subject("alice")).authorities(authorities("ROLE_USER")))
                    .get().uri("/bff/user/notifications")
                    .exchange()
                    .expectStatus().isOk();

            verify(service).list(eq("alice"), any(), eq(50));
        }

        @Test
        void markRead_authenticatedUser_isNoContent() {
            when(service.markRead(eq(UUID1), eq("alice"), any())).thenReturn(Mono.empty());

            client.mutateWith(mockJwt().jwt(j -> j.subject("alice")).authorities(authorities("ROLE_USER")))
                    .post().uri("/bff/user/notifications/" + UUID1 + "/read")
                    .exchange()
                    .expectStatus().isNoContent();

            verify(service).markRead(eq(UUID1), eq("alice"), any());
        }

        @Test
        void markRead_nonUuidId_isBadRequest_serviceNotReached() {
            client.mutateWith(mockJwt().jwt(j -> j.subject("alice")).authorities(authorities("ROLE_USER")))
                    .post().uri("/bff/user/notifications/not-a-uuid/read")
                    .exchange()
                    .expectStatus().isBadRequest();

            verify(service, never()).markRead(any(), any(), any());
        }

        @Test
        void list_overCapLimit_isBadRequest_serviceNotReached() {
            client.mutateWith(mockJwt().jwt(j -> j.subject("alice")).authorities(authorities("ROLE_USER")))
                    .get().uri("/bff/user/notifications?limit=99999")
                    .exchange()
                    .expectStatus().isBadRequest();

            verify(service, never()).list(any(), any(), org.mockito.ArgumentMatchers.anyInt());
        }
    }

    // ── CROSS-USER ────────────────────────────────────────────────────────────
    @Nested
    class CrossUser {
        @Test
        void list_ownerIsJwtSubject_notARequestField() {
            when(service.list(eq("bob"), any(), eq(50))).thenReturn(Mono.just(List.of()));

            client.mutateWith(mockJwt().jwt(j -> j.subject("bob")).authorities(authorities("ROLE_USER")))
                    .get().uri("/bff/user/notifications")
                    .exchange()
                    .expectStatus().isOk();

            verify(service).list(eq("bob"), any(), eq(50));
            verify(service, never()).list(eq("alice"), any(), org.mockito.ArgumentMatchers.anyInt());
        }

        @Test
        void markRead_ownerIsJwtSubject_notAPathField() {
            when(service.markRead(eq(UUID1), eq("bob"), any())).thenReturn(Mono.empty());

            client.mutateWith(mockJwt().jwt(j -> j.subject("bob")).authorities(authorities("ROLE_USER")))
                    .post().uri("/bff/user/notifications/" + UUID1 + "/read")
                    .exchange()
                    .expectStatus().isNoContent();

            verify(service).markRead(eq(UUID1), eq("bob"), any());
            verify(service, never()).markRead(any(), eq("alice"), any());
        }

        @Test
        void list_anonymous_isUnauthorized_serviceNotReached() {
            client.get().uri("/bff/user/notifications")
                    .exchange().expectStatus().isUnauthorized();
            verify(service, never()).list(any(), any(), org.mockito.ArgumentMatchers.anyInt());
        }

        @Test
        void markRead_anonymous_isUnauthorized_serviceNotReached() {
            client.post().uri("/bff/user/notifications/" + UUID1 + "/read")
                    .exchange().expectStatus().isUnauthorized();
            verify(service, never()).markRead(any(), any(), any());
        }
    }
}
