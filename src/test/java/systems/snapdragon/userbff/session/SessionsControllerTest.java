package systems.snapdragon.userbff.session;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webflux.test.autoconfigure.WebFluxTest;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Import;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.snapdragon.userbff.config.SecurityConfig;
import systems.snapdragon.userbff.session.SessionsInternalClient.BffSessionWire;

import java.time.LocalDateTime;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * Contract tests for {@code /bff/user/sessions} — the user-facing active-session feature.
 * Drives the real {@link SessionsController} + {@link SessionsService} with a MOCKED
 * {@link SessionsInternalClient} (no live admin-bff). Proves the security invariants:
 *
 * <ul>
 *   <li>unauthenticated ⇒ 401 (the ROLE_USER floor);</li>
 *   <li>a ROLE_USER caller lists ONLY their own sessions, scoped by the account derived
 *       SERVER-SIDE from the JWT (email ⇒ {@code google:<lc>}), and the raw bff_ token is
 *       NEVER in the response (only the opaque fingerprint id);</li>
 *   <li>the account passed to admin-bff is the JWT-derived one even when a {@code ?account=}
 *       param is supplied — the param is ignored;</li>
 *   <li>revoking the caller's own session resolves the id to the raw token and deletes it;</li>
 *   <li>revoking a FOREIGN/unknown id is a generic 404 and performs NO delete (cross-user
 *       isolation).</li>
 * </ul>
 */
@WebFluxTest(controllers = SessionsController.class)
// The @WebFluxTest slice does NOT scan @Service beans, so import the REAL SessionsService
// (its only collaborator, SessionsInternalClient, is the @MockitoBean below) — the tests
// exercise its real account-derivation + opaque-fingerprint + 404 logic.
@Import({SecurityConfig.class, SessionsService.class})
// Empty issuer-uri so DomainRegistry has an empty map; the ReactiveJwtDecoder is mocked, so
// no real JWT validation happens (matches AccountStatusControllerTest).
@TestPropertySource(properties = "spring.security.oauth2.resourceserver.jwt.issuer-uri=")
class SessionsControllerTest {

    @Autowired ApplicationContext context;
    WebTestClient client;

    @MockitoBean ReactiveJwtDecoder jwtDecoder;
    @MockitoBean SessionsInternalClient internal;

    private static final LocalDateTime NOW = LocalDateTime.of(2026, 6, 23, 12, 0);
    private static final LocalDateTime LATER = NOW.plusHours(12);

    // Alice's two raw tokens (NEVER returned to the browser — only their fingerprints are).
    private static final String ALICE_TOKEN_A = "bff_aliceTokenAAA";
    private static final String ALICE_TOKEN_B = "bff_aliceTokenBBB";

    @BeforeEach
    void setUpSecuredWebTestClient() {
        // Spring Security 7: the mockJwt() mutator only injects the SecurityContext when the
        // springSecurity() configurer's MutatorFilter is in the chain.
        client = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    private static BffSessionWire wire(String token) {
        return new BffSessionWire(token, "google:alice@example.com", NOW, LATER);
    }

    @Test
    void list_anonymous_isUnauthorized() {
        client.get().uri("/bff/user/sessions").exchange().expectStatus().isUnauthorized();
    }

    @Test
    void list_returnsOnlyMine_byJwtDerivedAccount_neverLeaksRawToken() {
        when(internal.sessionsForAccount(eq("google:alice@example.com")))
                .thenReturn(Flux.just(wire(ALICE_TOKEN_A), wire(ALICE_TOKEN_B)));

        client.mutateWith(mockJwt()
                        .jwt(j -> j.subject("alice").claim("email", "Alice@Example.com"))
                        .authorities(new SimpleGrantedAuthority("ROLE_USER")))
                .get().uri("/bff/user/sessions")
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                // opaque fingerprint ids present, raw tokens absent
                .jsonPath("$[0].id").isEqualTo(SessionsService.fingerprint(ALICE_TOKEN_A))
                .jsonPath("$[1].id").isEqualTo(SessionsService.fingerprint(ALICE_TOKEN_B))
                .jsonPath("$[0].createdAt").isNotEmpty()
                .jsonPath("$[0].expiresAt").isNotEmpty()
                .jsonPath("$[?(@.token)]").doesNotExist();

        // The email claim was lower-cased into google:<lc> — the production AuthController mapping.
        verify(internal).sessionsForAccount("google:alice@example.com");
    }

    @Test
    void list_derivesAccountFromJwt_ignoringAccountParam() {
        when(internal.sessionsForAccount(anyString())).thenReturn(Flux.empty());

        client.mutateWith(mockJwt()
                        .jwt(j -> j.subject("alice").claim("email", "alice@example.com"))
                        .authorities(new SimpleGrantedAuthority("ROLE_USER")))
                // attacker tries to scope to bob via a query param — it MUST be ignored
                .get().uri(uri -> uri.path("/bff/user/sessions").queryParam("account", "google:bob@example.com").build())
                .exchange()
                .expectStatus().isOk();

        // admin-bff was asked for ALICE's account (from the token), never bob's (the param).
        verify(internal).sessionsForAccount("google:alice@example.com");
        verify(internal, never()).sessionsForAccount("google:bob@example.com");
    }

    @Test
    void list_discordUser_mapsPreferredUsername_whenNoEmail() {
        when(internal.sessionsForAccount(eq("discord:zed"))).thenReturn(Flux.empty());

        client.mutateWith(mockJwt()
                        .jwt(j -> j.subject("zed").claim("preferred_username", "Zed"))
                        .authorities(new SimpleGrantedAuthority("ROLE_USER")))
                .get().uri("/bff/user/sessions")
                .exchange()
                .expectStatus().isOk();

        verify(internal).sessionsForAccount("discord:zed");
    }

    @Test
    void revoke_ownSession_resolvesIdToToken_andDeletes() {
        // The caller's own sessions (account-scoped server-side).
        when(internal.sessionsForAccount(eq("google:alice@example.com")))
                .thenReturn(Flux.just(wire(ALICE_TOKEN_A), wire(ALICE_TOKEN_B)));
        when(internal.deleteSession(eq(ALICE_TOKEN_B))).thenReturn(Mono.empty());

        String idB = SessionsService.fingerprint(ALICE_TOKEN_B);
        client.mutateWith(mockJwt()
                        .jwt(j -> j.subject("alice").claim("email", "alice@example.com"))
                        .authorities(new SimpleGrantedAuthority("ROLE_USER")))
                .delete().uri("/bff/user/sessions/{id}", idB)
                .exchange()
                .expectStatus().isNoContent();

        // The RAW token (resolved from the fingerprint over the caller's own list) is deleted.
        verify(internal).deleteSession(ALICE_TOKEN_B);
    }

    @Test
    void revoke_foreignId_isGenericNotFound_andDoesNotDelete() {
        // Alice owns only TOKEN_A; the id below is the fingerprint of a session she does NOT
        // own — it can never match her account-scoped list, so it must 404 with no delete.
        when(internal.sessionsForAccount(eq("google:alice@example.com")))
                .thenReturn(Flux.just(wire(ALICE_TOKEN_A)));

        String foreignId = SessionsService.fingerprint("bff_someoneElsesToken");
        client.mutateWith(mockJwt()
                        .jwt(j -> j.subject("alice").claim("email", "alice@example.com"))
                        .authorities(new SimpleGrantedAuthority("ROLE_USER")))
                .delete().uri("/bff/user/sessions/{id}", foreignId)
                .exchange()
                .expectStatus().isNotFound();

        // No delete was attempted for any token — cross-user revoke is structurally impossible.
        verify(internal, never()).deleteSession(anyString());
    }

    @Test
    void revoke_anonymous_isUnauthorized() {
        client.delete().uri("/bff/user/sessions/{id}", "anything")
                .exchange().expectStatus().isUnauthorized();
        verify(internal, never()).deleteSession(anyString());
    }
}
