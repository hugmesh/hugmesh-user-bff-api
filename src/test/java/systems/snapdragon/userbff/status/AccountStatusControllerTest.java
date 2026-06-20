package systems.snapdragon.userbff.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.boot.webflux.test.autoconfigure.WebFluxTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;
import systems.snapdragon.userbff.config.SecurityConfig;
import systems.snapdragon.userbff.silence.SelfSilence;
import systems.snapdragon.userbff.silence.SelfSilenceRepository;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

import org.springframework.test.context.TestPropertySource;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * FEAT-04 — account status polling endpoint contract tests.
 *
 * <ul>
 *   <li>Unauthenticated requests return 401.</li>
 *   <li>ROLE_USER callers reach the endpoint (ROLE_USER floor).</li>
 *   <li>With no silence row: {@code silenced:false}, no {@code silenceExpiresAt}.</li>
 *   <li>With an active silence row: {@code silenced:true} + {@code silenceExpiresAt}.</li>
 *   <li>Roles in the response derive from the JWT authorities (ROLE_* prefix stripped).</li>
 *   <li>Domain is derived from the token issuer (single-issuer → {@code "default"}).</li>
 * </ul>
 */
@WebFluxTest(controllers = AccountStatusController.class)
@Import(SecurityConfig.class)
// Clear the issuer-uri so DomainRegistry has an empty map → domainOf(any issuer) returns "default".
// The ReactiveJwtDecoder is mocked, so no real JWT validation happens; this only affects DomainRegistry.
@TestPropertySource(properties = "spring.security.oauth2.resourceserver.jwt.issuer-uri=")
class AccountStatusControllerTest {

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
    @MockitoBean SelfSilenceRepository silenceRepo;

    private static Instant inTwoHours() {
        return Instant.now().plus(2, ChronoUnit.HOURS);
    }

    @Test
    void status_anonymous_isUnauthorized() {
        client.get().uri("/bff/user/status").exchange().expectStatus().isUnauthorized();
    }

    @Test
    void status_noSilenceRow_returnsSilencedFalse() {
        when(silenceRepo.find(anyString(), anyString())).thenReturn(Mono.empty());

        client.mutateWith(mockJwt()
                        .jwt(j -> j.subject("alice"))
                        .authorities(new SimpleGrantedAuthority("ROLE_USER")))
                .get().uri("/bff/user/status")
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.sub").isEqualTo("alice")
                .jsonPath("$.silenced").isEqualTo(false)
                .jsonPath("$.silenceExpiresAt").doesNotExist()
                .jsonPath("$.roles").isArray()
                .jsonPath("$.domain").isEqualTo("default");
    }

    @Test
    void status_activeSilenceRow_returnsSilencedTrueWithExpiry() {
        Instant expiresAt = inTwoHours();
        SelfSilence active = new SelfSilence("alice", Instant.now(), expiresAt, null, "hiding", Instant.now());
        when(silenceRepo.find(anyString(), anyString())).thenReturn(Mono.just(active));

        client.mutateWith(mockJwt()
                        .jwt(j -> j.subject("alice"))
                        .authorities(new SimpleGrantedAuthority("ROLE_USER")))
                .get().uri("/bff/user/status")
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.silenced").isEqualTo(true)
                .jsonPath("$.silenceExpiresAt").isNotEmpty();
    }

    @Test
    void status_clearedSilenceRow_returnsSilencedFalse() {
        // A row with clearedAt set is NOT active — active() returns false.
        SelfSilence cleared = new SelfSilence("alice", Instant.now(), inTwoHours(), Instant.now(), "done", Instant.now());
        when(silenceRepo.find(anyString(), anyString())).thenReturn(Mono.just(cleared));

        client.mutateWith(mockJwt()
                        .jwt(j -> j.subject("alice"))
                        .authorities(new SimpleGrantedAuthority("ROLE_USER")))
                .get().uri("/bff/user/status")
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.silenced").isEqualTo(false);
    }

    @Test
    void status_rolesStrippedOfPrefix() {
        when(silenceRepo.find(anyString(), anyString())).thenReturn(Mono.empty());

        client.mutateWith(mockJwt()
                        .jwt(j -> j.subject("bob"))
                        .authorities(
                                new SimpleGrantedAuthority("ROLE_USER"),
                                new SimpleGrantedAuthority("ROLE_MATRIX"),
                                new SimpleGrantedAuthority("DOMAIN_default")))
                .get().uri("/bff/user/status")
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.roles[?(@ == 'USER')]").exists()
                .jsonPath("$.roles[?(@ == 'MATRIX')]").exists()
                .jsonPath("$.roles[?(@ == 'ROLE_USER')]").doesNotExist();
    }
}
