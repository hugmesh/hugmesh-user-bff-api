package systems.hugmesh.userbff.silence;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.boot.webflux.test.autoconfigure.WebFluxTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;
import systems.hugmesh.userbff.auth.AdminBffInternalClient;
import systems.hugmesh.userbff.auth.CanonicalIdentityResolver;
import systems.hugmesh.userbff.config.SecurityConfig;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Collection;
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
 * SELF-SILENCE controller surface test (owner-scoping + validation + access-unchanged)
 * via {@link WebTestClient} with synthetic authentications.
 * <ul>
 *   <li>activate/status/cancel require authentication (ROLE_USER floor); anonymous 401;</li>
 *   <li>owner is ALWAYS the JWT subject (the service is called with jwt.getSubject());</li>
 *   <li>activate validates a FUTURE expiresAt (past -> 400, service not called);</li>
 *   <li>ACCESS IS UNCHANGED: a self-silenced principal still reaches their own
 *       endpoints (status returns 200) — the silence never gates their own access.</li>
 * </ul>
 */
@WebFluxTest(controllers = SelfSilenceController.class)
@Import({SecurityConfig.class, CanonicalIdentityResolver.class})
class SelfSilenceControllerTest {

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
    @MockitoBean SelfSilenceService silence;
    @MockitoBean AdminBffInternalClient adminBff;

    private static Collection<GrantedAuthority> authorities(String... names) {
        List<GrantedAuthority> out = new ArrayList<>();
        for (String n : names) out.add(new SimpleGrantedAuthority(n));
        return out;
    }

    private static Instant soon() { return Instant.now().plus(2, ChronoUnit.HOURS); }

    @Test
    void activate_anonymous_isUnauthorized() {
        client.post().uri("/bff/user/self-silence/activate")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(Map.of("expiresAt", soon().toString()))
                .exchange()
                .expectStatus().isUnauthorized();
    }

    @Test
    void activate_ownerIsJwtSubject() {
        when(silence.activate(anyString(), anyString(), anyString(), any(), any(), any()))
                .thenReturn(Mono.just(new SelfSilence("alice", Instant.now(), soon(), null, "x", Instant.now())));
        client.mutateWith(mockJwt().jwt(j -> j.subject("alice")
                                .claim("localpart", "alice").claim("mastodon_localpart", "alice"))
                        .authorities(authorities("ROLE_USER")))
                .post().uri("/bff/user/self-silence/activate")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(Map.of("expiresAt", soon().toString(), "reason", "x"))
                .exchange()
                .expectStatus().isOk();
        verify(silence).activate(org.mockito.ArgumentMatchers.eq("alice"),
                org.mockito.ArgumentMatchers.eq("alice"), org.mockito.ArgumentMatchers.eq("alice"),
                any(), any(), any());
    }

    @Test
    void activate_pastExpiry_is400_serviceNotCalled() {
        client.mutateWith(mockJwt().jwt(j -> j.subject("alice")).authorities(authorities("ROLE_USER")))
                .post().uri("/bff/user/self-silence/activate")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(Map.of("expiresAt", Instant.now().minusSeconds(60).toString()))
                .exchange()
                .expectStatus().isBadRequest();
        verify(silence, never()).activate(anyString(), anyString(), anyString(), any(), any(), any());
    }

    @Test
    void status_silencedUser_stillReachesOwnEndpoint_accessUnchanged() {
        // A self-silenced principal is NOT gated from their own surface: status 200.
        when(silence.status(eq("alice"), any()))
                .thenReturn(Mono.just(new SelfSilence("alice", Instant.now(), soon(), null, "afk", Instant.now())));
        client.mutateWith(mockJwt().jwt(j -> j.subject("alice")).authorities(authorities("ROLE_USER")))
                .get().uri("/bff/user/self-silence/status")
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.userId").isEqualTo("alice");
    }

    @Test
    void cancel_returnsNoContent() {
        when(silence.cancel(eq("alice"), eq("alice"), eq("alice"), any())).thenReturn(Mono.empty());
        client.mutateWith(mockJwt().jwt(j -> j.subject("alice")
                                .claim("localpart", "alice").claim("mastodon_localpart", "alice"))
                        .authorities(authorities("ROLE_USER")))
                .post().uri("/bff/user/self-silence/cancel")
                .exchange()
                .expectStatus().isNoContent();
    }

    @Test
    void emailMod_writesReactivationRequest() {
        when(silence.requestEarlyReactivation(eq("alice"), eq("please"), any()))
                .thenReturn(Mono.just(Map.of("requested", true)));
        client.mutateWith(mockJwt().jwt(j -> j.subject("alice")).authorities(authorities("ROLE_USER")))
                .post().uri("/bff/user/self-silence/email-mod")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(Map.of("reason", "please"))
                .exchange()
                .expectStatus().isOk()
                .expectBody().jsonPath("$.requested").isEqualTo(true);
    }
}
