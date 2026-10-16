package net.hugmesh.userbff.notification;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webflux.test.autoconfigure.WebFluxTest;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Import;
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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * Slice test for {@link InternalNotificationPreferenceController} via {@link WebTestClient},
 * importing the REAL {@link SecurityConfig} so the {@code /bff/user/internal/**} route gate
 * and the {@code @PreAuthorize("hasRole('SERVICE')")} method gate are both in play; the
 * {@link NotificationPreferenceService} is mocked.
 *
 * <ul>
 *   <li><b>SERVICE-ONLY GATE</b> - USER / ADMIN / MOD / SUPERADMIN are 403, anonymous is
 *       401, and the service is never reached; only {@code ROLE_SERVICE} reads.</li>
 *   <li><b>DOMAIN SCOPE</b> - the owner comes from the path and the domain from the required
 *       query parameter, and BOTH reach the service as concrete values. A missing, blank or
 *       malformed domain is a 400 (a null domain would be the service's cross-domain
 *       bypass).</li>
 *   <li><b>CONTRACT</b> - the body is the service's resolved map unchanged, including
 *       {@code account-restriction=true}.</li>
 * </ul>
 */
@WebFluxTest(controllers = InternalNotificationPreferenceController.class)
@Import(SecurityConfig.class)
@EnableReactiveMethodSecurity
class InternalNotificationPreferenceControllerTest {

    private static final String PATH = "/bff/user/internal/notification-preferences/";

    @Autowired ApplicationContext context;
    WebTestClient client;

    // Spring Security 7: the mockJwt() mutators only inject the SecurityContext when the
    // springSecurity() configurer is applied, so build the client from the context.
    @BeforeEach
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

    private WebTestClient.RequestHeadersSpec<?> asService(String uri) {
        return client.mutateWith(mockJwt().jwt(j -> j.subject("admin-bff"))
                        .authorities(authorities("ROLE_SERVICE")))
                .get().uri(uri);
    }

    private static Map<String, Boolean> resolved(boolean roleChange) {
        Map<String, Boolean> m = new LinkedHashMap<>();
        m.put(NotificationCategory.ACCOUNT_RESTRICTION, true);
        m.put(NotificationCategory.ROLE_CHANGE, roleChange);
        m.put(NotificationCategory.INFRA_IMPACTING, true);
        m.put(NotificationCategory.FEATURE_AVAILABILITY, true);
        return m;
    }

    @Nested
    class ServiceOnlyGate {

        @Test
        void servicePrincipal_reads() {
            when(service.get(eq("victim-user"), eq("brandx"))).thenReturn(Mono.just(resolved(false)));

            asService(PATH + "victim-user?domain=brandx")
                    .exchange()
                    .expectStatus().isOk();

            verify(service).get("victim-user", "brandx");
        }

        @Test
        void normalUser_isForbidden_serviceNeverReached() {
            client.mutateWith(mockJwt().jwt(j -> j.subject("victim-user"))
                            .authorities(authorities("ROLE_USER")))
                    .get().uri(PATH + "victim-user?domain=brandx")
                    .exchange()
                    .expectStatus().isForbidden();

            verify(service, never()).get(anyString(), any());
        }

        @Test
        void adminModAndSuperadmin_areForbidden_serviceNeverReached() {
            for (String role : List.of("ROLE_ADMIN", "ROLE_MOD", "ROLE_SUPERADMIN")) {
                client.mutateWith(mockJwt().jwt(j -> j.subject("human"))
                                .authorities(authorities("ROLE_USER", role)))
                        .get().uri(PATH + "victim-user?domain=brandx")
                        .exchange()
                        .expectStatus().isForbidden();
            }

            verify(service, never()).get(anyString(), any());
        }

        @Test
        void anonymous_isUnauthorized_serviceNeverReached() {
            client.get().uri(PATH + "victim-user?domain=brandx")
                    .exchange()
                    .expectStatus().isUnauthorized();

            verify(service, never()).get(anyString(), any());
        }
    }

    @Nested
    class DomainScope {

        @Test
        void missingDomain_isBadRequest_serviceNeverReached() {
            asService(PATH + "victim-user").exchange().expectStatus().isBadRequest();

            verify(service, never()).get(anyString(), any());
        }

        @Test
        void blankDomain_isBadRequest_serviceNeverReached() {
            asService(PATH + "victim-user?domain=").exchange().expectStatus().isBadRequest();

            verify(service, never()).get(anyString(), any());
        }

        @Test
        void malformedDomain_isBadRequest_serviceNeverReached() {
            asService(PATH + "victim-user?domain=bad%20domain%3B").exchange().expectStatus().isBadRequest();

            verify(service, never()).get(anyString(), any());
        }
    }

    @Nested
    class Contract {

        @Test
        void returnsTheResolvedMap_accountRestrictionStaysEnabled() {
            when(service.get(eq("victim-user"), eq("brandx"))).thenReturn(Mono.just(resolved(false)));

            asService(PATH + "victim-user?domain=brandx")
                    .exchange()
                    .expectStatus().isOk()
                    .expectBody()
                    .jsonPath("$.account-restriction").isEqualTo(true)
                    .jsonPath("$.role-change").isEqualTo(false)
                    .jsonPath("$.infra-impacting").isEqualTo(true)
                    .jsonPath("$.feature-availability").isEqualTo(true);
        }
    }
}
