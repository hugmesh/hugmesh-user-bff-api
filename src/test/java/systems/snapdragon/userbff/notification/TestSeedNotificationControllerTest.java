package systems.snapdragon.userbff.notification;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webflux.test.autoconfigure.WebFluxTest;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;
import systems.snapdragon.userbff.config.SecurityConfig;
import systems.snapdragon.userbff.notification.InternalNotificationDeliveryService.DeliveryResult;

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
 * Slice test for {@link TestSeedNotificationController} with {@code app.test-seed.enabled=true}
 * (the e2e/dev deployment configuration), importing the REAL {@link SecurityConfig} so the
 * {@code /bff/user/**} ROLE_USER floor + {@code @PreAuthorize("hasRole('USER')")} method gate
 * are exercised; {@link InternalNotificationDeliveryService} is mocked. Delineated per the test
 * standard:
 *
 * <ul>
 *   <li><b>USER-SITUATIONAL ALLOW</b> — an authenticated ROLE_USER principal seeds a
 *       notification for themselves through the SAME delivery service the production
 *       ROLE_SERVICE deliver path calls; the response carries the deterministic id.</li>
 *   <li><b>SELF-ONLY (the anti-IDOR proof)</b> — the target passed to the delivery service is
 *       ALWAYS the caller's own JWT subject/domain, verified even though the request carries no
 *       target field to spoof in the first place — this is the "no new IDOR" contract test.</li>
 *   <li><b>FAIL-CLOSED</b> — anonymous is 401; a SUPERADMIN's cross-domain (null) scope is
 *       refused (400), not silently defaulted; an unknown/malformed category is 400; the service
 *       is NEVER reached on any of these.</li>
 *   <li><b>IDEMPOTENCY</b> — the same {@code sourceId} run twice yields {@code deduped=true} on
 *       the second call, and the returned {@code id} is identical both times (proving it is
 *       computed the same deterministic way the production path computes it).</li>
 * </ul>
 */
@WebFluxTest(controllers = TestSeedNotificationController.class)
@Import(SecurityConfig.class)
@EnableReactiveMethodSecurity
@TestPropertySource(properties = "app.test-seed.enabled=true")
class TestSeedNotificationControllerTest {

    @Autowired ApplicationContext context;
    WebTestClient client;

    @org.junit.jupiter.api.BeforeEach
    void setUpSecuredWebTestClient() {
        client = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    @MockitoBean ReactiveJwtDecoder jwtDecoder;
    @MockitoBean InternalNotificationDeliveryService service;

    private static final String PATH = "/bff/user/notifications/test-seed";

    private static Collection<GrantedAuthority> authorities(String... names) {
        List<GrantedAuthority> out = new ArrayList<>();
        for (String n : names) out.add(new SimpleGrantedAuthority(n));
        return out;
    }

    // ── USER-SITUATIONAL ALLOW ───────────────────────────────────────────────
    @Nested
    class UserSituationalAllow {

        @Test
        void authenticatedUser_seedsOwnNotification_throughProductionDeliveryService() {
            when(service.deliver(any(), eq("alice"), eq(NotificationCategory.ROLE_CHANGE),
                    any(), any(), eq(TestSeedNotificationController.SEED_SOURCE_TABLE), any()))
                    .thenReturn(Mono.just(new DeliveryResult(true, false, null)));

            client.mutateWith(mockJwt().jwt(j -> j.subject("alice")).authorities(authorities("ROLE_USER")))
                    .post().uri(PATH)
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(Map.of("category", NotificationCategory.ROLE_CHANGE,
                            "title", "You got a new role", "body", "seed-e2e fixture"))
                    .exchange()
                    .expectStatus().isOk()
                    .expectBody()
                    .jsonPath("$.delivered").isEqualTo(true)
                    .jsonPath("$.deduped").isEqualTo(false)
                    .jsonPath("$.id").isNotEmpty();

            verify(service).deliver(any(), eq("alice"), eq(NotificationCategory.ROLE_CHANGE),
                    eq("You got a new role"), eq("seed-e2e fixture"),
                    eq(TestSeedNotificationController.SEED_SOURCE_TABLE), any());
        }

        @Test
        void titleDefaultsWhenOmitted() {
            when(service.deliver(any(), eq("alice"), any(), any(), any(), any(), any()))
                    .thenReturn(Mono.just(new DeliveryResult(true, false, null)));

            client.mutateWith(mockJwt().jwt(j -> j.subject("alice")).authorities(authorities("ROLE_USER")))
                    .post().uri(PATH)
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(Map.of("category", NotificationCategory.INFRA_IMPACTING))
                    .exchange()
                    .expectStatus().isOk();

            verify(service).deliver(any(), eq("alice"), eq(NotificationCategory.INFRA_IMPACTING),
                    eq("Test-seed notification"), any(), any(), any());
        }
    }

    // ── SELF-ONLY (the anti-IDOR proof) ──────────────────────────────────────
    @Nested
    class SelfOnly {

        @Test
        void targetIsAlwaysCallerJwtSubject_neverAnotherUser() {
            when(service.deliver(any(), any(), any(), any(), any(), any(), any()))
                    .thenReturn(Mono.just(new DeliveryResult(true, false, null)));

            client.mutateWith(mockJwt().jwt(j -> j.subject("bob")).authorities(authorities("ROLE_USER")))
                    .post().uri(PATH)
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(Map.of("category", NotificationCategory.ROLE_CHANGE))
                    .exchange()
                    .expectStatus().isOk();

            // The seed request carries NO target field at all — this proves the service was
            // invoked with the caller's OWN subject, never any other identity.
            verify(service).deliver(any(), eq("bob"), any(), any(), any(), any(), any());
            verify(service, never()).deliver(any(), eq("alice"), any(), any(), any(), any(), any());
        }
    }

    // ── FAIL-CLOSED ───────────────────────────────────────────────────────────
    @Nested
    class FailClosed {

        @Test
        void anonymous_isUnauthorized_serviceNeverReached() {
            client.post().uri(PATH)
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(Map.of("category", NotificationCategory.ROLE_CHANGE))
                    .exchange()
                    .expectStatus().isUnauthorized();

            verify(service, never()).deliver(any(), any(), any(), any(), any(), any(), any());
        }

        @Test
        void superadminCrossDomainPrincipal_isBadRequest_serviceNeverReached() {
            // SUPERADMIN resolves PrincipalDomain.forScope() -> null (the cross-domain
            // bypass) — there is no single concrete domain to seed a fixture into, so the
            // endpoint refuses rather than guessing one. Roles.isSuperadmin(Jwt) reads the
            // RAW "roles" claim (not the converted Spring authorities), so both must be set.
            client.mutateWith(mockJwt()
                            .jwt(j -> j.subject("root").claim("roles", List.of("superadmin")))
                            .authorities(authorities("ROLE_USER", "ROLE_SUPERADMIN")))
                    .post().uri(PATH)
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(Map.of("category", NotificationCategory.ROLE_CHANGE))
                    .exchange()
                    .expectStatus().isBadRequest();

            verify(service, never()).deliver(any(), any(), any(), any(), any(), any(), any());
        }

        @Test
        void badCategory_isBadRequest_serviceNeverReached() {
            client.mutateWith(mockJwt().jwt(j -> j.subject("alice")).authorities(authorities("ROLE_USER")))
                    .post().uri(PATH)
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(Map.of("category", "Not_A_Category"))
                    .exchange()
                    .expectStatus().isBadRequest();

            verify(service, never()).deliver(any(), any(), any(), any(), any(), any(), any());
        }

        @Test
        void missingCategory_isBadRequest_serviceNeverReached() {
            client.mutateWith(mockJwt().jwt(j -> j.subject("alice")).authorities(authorities("ROLE_USER")))
                    .post().uri(PATH)
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(Map.of())
                    .exchange()
                    .expectStatus().isBadRequest();

            verify(service, never()).deliver(any(), any(), any(), any(), any(), any(), any());
        }
    }

    // ── IDEMPOTENCY ────────────────────────────────────────────────────────────
    @Nested
    class Idempotency {

        @Test
        void sameSourceId_secondCallIsDeduped_sameId() {
            when(service.deliver(any(), eq("alice"), any(), any(), any(), any(), eq("fixture-1")))
                    .thenReturn(Mono.just(new DeliveryResult(true, false, null)))
                    .thenReturn(Mono.just(new DeliveryResult(true, true, null)));

            Map<String, Object> body = Map.of("category", NotificationCategory.ROLE_CHANGE, "sourceId", "fixture-1");

            byte[] firstResponse = client.mutateWith(mockJwt().jwt(j -> j.subject("alice")).authorities(authorities("ROLE_USER")))
                    .post().uri(PATH)
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(body)
                    .exchange()
                    .expectStatus().isOk()
                    .expectBody()
                    .jsonPath("$.deduped").isEqualTo(false)
                    .jsonPath("$.id").isNotEmpty()
                    .returnResult().getResponseBody();

            // second call: same sourceId -> deduped=true, and the id must match the first
            // call's id byte-for-byte (both are computed via the SAME deterministic
            // StableNotificationId.forInApp(sourceTable, sourceId) the controller uses).
            byte[] secondResponse = client.mutateWith(mockJwt().jwt(j -> j.subject("alice")).authorities(authorities("ROLE_USER")))
                    .post().uri(PATH)
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(body)
                    .exchange()
                    .expectStatus().isOk()
                    .expectBody()
                    .jsonPath("$.deduped").isEqualTo(true)
                    .returnResult().getResponseBody();

            String firstId = extractId(firstResponse);
            String secondId = extractId(secondResponse);
            org.assertj.core.api.Assertions.assertThat(secondId)
                    .as("the deterministic seed id must be identical across a deduped retry")
                    .isEqualTo(firstId)
                    .isEqualTo(StableNotificationId.forInApp(
                            TestSeedNotificationController.SEED_SOURCE_TABLE, "fixture-1"));
        }

        private String extractId(byte[] responseBody) {
            org.assertj.core.api.Assertions.assertThat(responseBody).isNotNull();
            String json = new String(responseBody, java.nio.charset.StandardCharsets.UTF_8);
            java.util.regex.Matcher m = java.util.regex.Pattern.compile("\"id\":\"([^\"]+)\"").matcher(json);
            org.assertj.core.api.Assertions.assertThat(m.find()).as("response must carry an id field").isTrue();
            return m.group(1);
        }
    }
}
