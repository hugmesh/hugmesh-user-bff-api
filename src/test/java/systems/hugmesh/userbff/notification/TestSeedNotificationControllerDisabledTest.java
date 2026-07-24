package systems.hugmesh.userbff.notification;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webflux.test.autoconfigure.WebFluxTest;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import systems.hugmesh.userbff.config.SecurityConfig;

import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * {@link TestSeedNotificationController} in its DEFAULT (production) configuration —
 * {@code app.test-seed.enabled} is NOT set, so it falls back to {@code false}. Proves the
 * HONEST-DISCLOSURE invariant: a disabled seed route must not silently succeed while doing
 * nothing. Every call — even from a genuine, authenticated ROLE_USER principal — gets a real
 * 503 and the delivery service is NEVER reached (zero writes).
 *
 * <p>Separate test class (not a nested case in {@link TestSeedNotificationControllerTest})
 * because the flag is read once at controller-construction time from {@code @Value}; a
 * distinct default-properties Spring context is the only way to exercise "flag genuinely
 * absent" rather than "flag explicitly true".
 */
@WebFluxTest(controllers = TestSeedNotificationController.class)
@Import(SecurityConfig.class)
@EnableReactiveMethodSecurity
class TestSeedNotificationControllerDisabledTest {

    @Autowired ApplicationContext context;
    WebTestClient client;

    @org.junit.jupiter.api.BeforeEach
    void setUpSecuredWebTestClient() {
        client = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    @MockitoBean ReactiveJwtDecoder jwtDecoder;
    @MockitoBean InternalNotificationDeliveryService service;

    private static final String PATH = "/bff/user/notifications/test-seed";

    @Test
    void defaultFlagOff_authenticatedUser_is503_serviceNeverReached() {
        client.mutateWith(mockJwt().jwt(j -> j.subject("alice")).authorities(
                        new org.springframework.security.core.authority.SimpleGrantedAuthority("ROLE_USER")))
                .post().uri(PATH)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(Map.of("category", NotificationCategory.ROLE_CHANGE))
                .exchange()
                .expectStatus().isEqualTo(503);

        verify(service, never()).deliver(any(), any(), any(), any(), any(), any(), any());
    }
}
