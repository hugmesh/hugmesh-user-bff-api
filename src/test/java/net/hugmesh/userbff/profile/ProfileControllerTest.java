package net.hugmesh.userbff.profile;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.boot.webflux.test.autoconfigure.WebFluxTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;
import net.hugmesh.userbff.auth.AdminBffInternalClient;
import net.hugmesh.userbff.auth.AdminBffInternalClient.AccountView;
import net.hugmesh.userbff.config.SecurityConfig;
import net.hugmesh.userbff.security.PrincipalDomain;

import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * HTTP-layer security tests for {@link ProfileController}.
 *
 * <ul>
 *   <li>{@code anonymous_isUnauthorized} — GET and PUT without a token return 401.</li>
 *   <li>{@code roleUser_canReadOwnProfile} — GET /bff/user/profile → 200, service
 *       called with JWT subject as owner.</li>
 *   <li>{@code roleUser_canUpdateProfile} — PUT /bff/user/profile → 200, service
 *       called with JWT subject as owner.</li>
 *   <li>{@code crossOwner_jwtSubjectEnforced} — the body's userId is ignored; the JWT
 *       subject is always the authoritative owner passed to the service.</li>
 * </ul>
 *
 * <p>{@link ProfileService} is mocked so these tests stay at the HTTP boundary.
 * {@code @TestPropertySource} clears the issuer-uri so {@code DomainRegistry} yields
 * {@code "default"} for any issuer (no real JWT validation).
 */
@WebFluxTest(controllers = ProfileController.class)
@Import(SecurityConfig.class)
@TestPropertySource(properties = "spring.security.oauth2.resourceserver.jwt.issuer-uri=")
class ProfileControllerTest {

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
    @MockitoBean ProfileService profiles;
    @MockitoBean AvatarService avatars;
    @MockitoBean PrincipalDomain principalDomain;
    // Present so BffSessionAuthenticationWebFilter — auto-discovered into this
    // @WebFluxTest slice like any other @Component WebFilter — has something to call
    // for the bff_-session tests below; absent/disabled for every mockJwt() test above
    // (enabled() defaults to Mockito's false), so those are completely unaffected.
    @MockitoBean AdminBffInternalClient adminBffClient;

    private static UserProfile stubProfile(String userId) {
        return new UserProfile(userId, null, null, null, "Display", "internal", false, null, null);
    }

    @Test
    void anonymous_getProfile_isUnauthorized() {
        client.get().uri("/bff/user/profile")
                .exchange()
                .expectStatus().isUnauthorized();
        verify(profiles, never()).get(anyString(), anyString());
    }

    @Test
    void anonymous_putProfile_isUnauthorized() {
        client.put().uri("/bff/user/profile")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(stubProfile("alice"))
                .exchange()
                .expectStatus().isUnauthorized();
        verify(profiles, never()).save(anyString(), anyString(), any(), any());
    }

    @Test
    void roleUser_canReadOwnProfile() {
        when(principalDomain.forScope(any())).thenReturn("default");
        when(profiles.get(eq("alice"), eq("default")))
                .thenReturn(Mono.just(stubProfile("alice")));

        client.mutateWith(mockJwt()
                        .jwt(j -> j.subject("alice"))
                        .authorities(new SimpleGrantedAuthority("ROLE_USER")))
                .get().uri("/bff/user/profile")
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.userId").isEqualTo("alice");

        verify(profiles).get(eq("alice"), eq("default"));
    }

    @Test
    void roleUser_canUpdateProfile() {
        when(principalDomain.forScope(any())).thenReturn("default");
        when(profiles.save(eq("alice"), anyString(), any(), eq("default")))
                .thenReturn(Mono.just(stubProfile("alice")));

        client.mutateWith(mockJwt()
                        .jwt(j -> j.subject("alice").claim("preferred_username", "alice"))
                        .authorities(new SimpleGrantedAuthority("ROLE_USER")))
                .put().uri("/bff/user/profile")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(stubProfile("alice"))
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.userId").isEqualTo("alice");

        verify(profiles).save(eq("alice"), eq("alice"), any(), eq("default"));
    }

    @Test
    void crossOwner_jwtSubjectEnforced_bodyUserIdIsIgnored() {
        // The body contains a spoofed userId ("bob") but the JWT subject is "alice".
        // The service must always be called with the JWT subject ("alice"), never the
        // body's userId — the controller extracts owner from the token, not the body.
        when(principalDomain.forScope(any())).thenReturn("default");
        when(profiles.save(eq("alice"), anyString(), any(), eq("default")))
                .thenReturn(Mono.just(stubProfile("alice")));

        client.mutateWith(mockJwt()
                        .jwt(j -> j.subject("alice").claim("preferred_username", "alice"))
                        .authorities(new SimpleGrantedAuthority("ROLE_USER")))
                .put().uri("/bff/user/profile")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(stubProfile("bob"))      // spoofed userId in body
                .exchange()
                .expectStatus().isOk();

        // Service was called with "alice" (JWT subject), never "bob" (body field).
        verify(profiles).save(eq("alice"), eq("alice"), any(), eq("default"));
        verify(profiles, never()).save(eq("bob"), anyString(), any(), any());
    }

    // ── BUG 2 self-review: a REAL Jwt-typed controller, driven by a bff_ session,
    //    through the REAL BffSessionAuthenticationWebFilter (auto-discovered into this
    //    slice, not hand-constructed) + the REAL SecurityConfig chain. No mockJwt()
    //    mutator anywhere below — the Jwt principal ProfileController.me() receives is
    //    entirely the synthetic one BffSessionAuthenticationWebFilter built. Pre-fix,
    //    @AuthenticationPrincipal Jwt jwt resolved to null for a String-principal
    //    Authentication, and jwt.getSubject() (the FIRST expression evaluated inside
    //    profiles.get(jwt.getSubject(), ...)) NPE'd before principalDomain.forScope was
    //    ever reached — live-reproduced by the reviewer as a 500. ──────────────────────

    @Test
    void bffSessionHeader_realJwtTypedController_noNpe_returns200() {
        AccountView view = new AccountView("acct-bff-1", "native", "bffuser", true, List.of("user"), "lp");
        when(adminBffClient.enabled()).thenReturn(true);
        when(adminBffClient.resolveSession("bff_profiletoken")).thenReturn(Mono.just(new AdminBffInternalClient.SessionResolution(view, "active", false)));
        when(principalDomain.forScope(any())).thenReturn("default");
        when(profiles.get(eq("acct-bff-1"), eq("default")))
                .thenReturn(Mono.just(stubProfile("acct-bff-1")));

        client.get().uri("/bff/user/profile")
                .header("Authorization", "Bearer bff_profiletoken")
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.userId").isEqualTo("acct-bff-1");

        verify(profiles).get(eq("acct-bff-1"), eq("default"));
    }

    @Test
    void bffSessionCookie_realJwtTypedController_noNpe_returns200() {
        // Same proof, cookie carrier — SsoAuthController's own documented native-login
        // convention, and the ONLY carrier BffSessionAuthenticationSliceTest's probe-
        // controller-based coverage exercised before this PR.
        AccountView view = new AccountView("acct-bff-2", "native", "bffuser2", true, List.of("user"), "lp");
        when(adminBffClient.enabled()).thenReturn(true);
        when(adminBffClient.resolveSession("bff_profilecookie")).thenReturn(Mono.just(new AdminBffInternalClient.SessionResolution(view, "active", false)));
        when(principalDomain.forScope(any())).thenReturn("default");
        when(profiles.get(eq("acct-bff-2"), eq("default")))
                .thenReturn(Mono.just(stubProfile("acct-bff-2")));

        client.get().uri("/bff/user/profile")
                .cookie("bff_session", "bff_profilecookie")
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.userId").isEqualTo("acct-bff-2");

        verify(profiles).get(eq("acct-bff-2"), eq("default"));
    }
}
