package systems.hugmesh.userbff.notification;

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
import systems.hugmesh.userbff.notification.InternalNotificationDeliveryService.DeliveryResult;

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
 * Slice test for {@link InternalNotificationController} via {@link WebTestClient},
 * importing the REAL {@link SecurityConfig} so the {@code /bff/user/internal/**} route
 * gate AND the {@code @PreAuthorize("hasRole('SERVICE')")} method gate are exercised;
 * the {@link InternalNotificationDeliveryService} is mocked. This is the CORE PRIVILEGE
 * BOUNDARY test: the endpoint takes its target {@code (domain, userSubject)} from the
 * BODY, so a human reaching it would be a notification-spoofing IDOR — only the SERVICE
 * principal may succeed. Delineated per the test standard:
 *
 * <ul>
 *   <li><b>SERVICE-ONLY GATE (the IDOR test)</b> — a normal USER / ADMIN / MOD /
 *       SUPERADMIN JWT is DENIED (403) and the service is NEVER reached; an anonymous
 *       request is 401; ONLY a {@code ROLE_SERVICE} principal succeeds.</li>
 *   <li><b>CONTRACT</b> — a valid SERVICE call passes the body's target verbatim to the
 *       service and returns its {@code DeliveryResult}; a bad-vocabulary / missing field
 *       is a 400 at the validation boundary.</li>
 * </ul>
 */
@WebFluxTest(controllers = InternalNotificationController.class)
@Import(SecurityConfig.class)
@EnableReactiveMethodSecurity
class InternalNotificationControllerTest {

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
    @MockitoBean InternalNotificationDeliveryService service;

    private static final String PATH = "/bff/user/internal/notifications";

    private static Collection<GrantedAuthority> authorities(String... names) {
        List<GrantedAuthority> out = new ArrayList<>();
        for (String n : names) out.add(new SimpleGrantedAuthority(n));
        return out;
    }

    /** A complete, valid deliver body (target taken from the body, not any JWT). */
    private static Map<String, Object> validBody() {
        Map<String, Object> b = new java.util.LinkedHashMap<>();
        b.put("domain", "brandx");
        b.put("userSubject", "victim-user");
        b.put("category", NotificationCategory.ROLE_CHANGE);
        b.put("title", "Your role changed");
        b.put("body", "You were granted MOD.");
        b.put("sourceTable", "role_grant");
        b.put("sourceId", "rg-123");
        return b;
    }

    // ── SERVICE-ONLY GATE (the IDOR boundary) ─────────────────────────────────
    @Nested
    class ServiceOnlyGate {

        @Test
        void servicePrincipal_succeeds_andTargetComesFromBody() {
            when(service.deliver(eq("brandx"), eq("victim-user"), eq(NotificationCategory.ROLE_CHANGE),
                    eq("Your role changed"), eq("You were granted MOD."), eq("role_grant"), eq("rg-123")))
                    .thenReturn(Mono.just(new DeliveryResult(true, false, null)));

            client.mutateWith(mockJwt().jwt(j -> j.subject("hugmesh-actions"))
                            .authorities(authorities("ROLE_SERVICE")))
                    .post().uri(PATH)
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(validBody())
                    .exchange()
                    .expectStatus().isOk()
                    .expectBody()
                    .jsonPath("$.delivered").isEqualTo(true)
                    .jsonPath("$.deduped").isEqualTo(false);

            // the TARGET is the body's (brandx, victim-user) — NOT the caller's subject.
            verify(service).deliver(eq("brandx"), eq("victim-user"), any(), any(), any(), any(), any());
        }

        @Test
        void normalUser_isForbidden_serviceNeverReached() {
            client.mutateWith(mockJwt().jwt(j -> j.subject("mallory"))
                            .authorities(authorities("ROLE_USER")))
                    .post().uri(PATH)
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(validBody())
                    .exchange()
                    .expectStatus().isForbidden();

            verify(service, never()).deliver(any(), any(), any(), any(), any(), any(), any());
        }

        @Test
        void admin_isForbidden_serviceNeverReached() {
            client.mutateWith(mockJwt().jwt(j -> j.subject("an-admin"))
                            .authorities(authorities("ROLE_USER", "ROLE_ADMIN")))
                    .post().uri(PATH)
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(validBody())
                    .exchange()
                    .expectStatus().isForbidden();

            verify(service, never()).deliver(any(), any(), any(), any(), any(), any(), any());
        }

        @Test
        void mod_isForbidden_serviceNeverReached() {
            client.mutateWith(mockJwt().jwt(j -> j.subject("a-mod"))
                            .authorities(authorities("ROLE_USER", "ROLE_MOD")))
                    .post().uri(PATH)
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(validBody())
                    .exchange()
                    .expectStatus().isForbidden();

            verify(service, never()).deliver(any(), any(), any(), any(), any(), any(), any());
        }

        @Test
        void superadmin_isForbidden_serviceNeverReached() {
            // SUPERADMIN is the cross-domain infra super-role, but the role hierarchy has
            // NO edge to ROLE_SERVICE — so even SUPERADMIN cannot reach the deliver path
            // (it would otherwise be a human able to spoof to ANY user).
            client.mutateWith(mockJwt().jwt(j -> j.subject("a-superadmin"))
                            .authorities(authorities("ROLE_USER", "ROLE_SUPERADMIN")))
                    .post().uri(PATH)
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(validBody())
                    .exchange()
                    .expectStatus().isForbidden();

            verify(service, never()).deliver(any(), any(), any(), any(), any(), any(), any());
        }

        @Test
        void anonymous_isUnauthorized_serviceNeverReached() {
            client.post().uri(PATH)
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(validBody())
                    .exchange()
                    .expectStatus().isUnauthorized();

            verify(service, never()).deliver(any(), any(), any(), any(), any(), any(), any());
        }
    }

    // ── CONTRACT / VALIDATION ─────────────────────────────────────────────────
    @Nested
    class Contract {

        @Test
        void servicePrincipal_badCategory_isBadRequest_serviceNotReached() {
            Map<String, Object> bad = validBody();
            bad.put("category", "Not_A_Category");   // breaks the lower-alpha pattern

            client.mutateWith(mockJwt().jwt(j -> j.subject("hugmesh-actions"))
                            .authorities(authorities("ROLE_SERVICE")))
                    .post().uri(PATH)
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(bad)
                    .exchange()
                    .expectStatus().isBadRequest();

            verify(service, never()).deliver(any(), any(), any(), any(), any(), any(), any());
        }

        @Test
        void servicePrincipal_missingSourceId_isBadRequest_serviceNotReached() {
            Map<String, Object> bad = validBody();
            bad.remove("sourceId");

            client.mutateWith(mockJwt().jwt(j -> j.subject("hugmesh-actions"))
                            .authorities(authorities("ROLE_SERVICE")))
                    .post().uri(PATH)
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(bad)
                    .exchange()
                    .expectStatus().isBadRequest();

            verify(service, never()).deliver(any(), any(), any(), any(), any(), any(), any());
        }
    }
}
