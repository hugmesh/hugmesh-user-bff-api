package systems.snapdragon.userbff.block;

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
import systems.snapdragon.userbff.config.SecurityConfig;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * METHOD-LEVEL {@code @PreAuthorize} (API leg) test for the BlockController
 * platform-role gate, driven through {@link WebTestClient} with synthetic
 * authentications. Proves the gate denies at the HTTP boundary BEFORE the service is
 * even called:
 * <ul>
 *   <li>{@code matrix} block without {@code ROLE_MATRIX} -> 403 (service never invoked);</li>
 *   <li>{@code mastodon} block without {@code ROLE_MASTODON} -> 403;</li>
 *   <li>with the matching platform role -> reaches the service (200);</li>
 *   <li>{@code internal} block needs only the ROLE_USER floor;</li>
 *   <li>recommend-instance-block needs a platform role (403 without one).</li>
 * </ul>
 */
@WebFluxTest(controllers = BlockController.class)
@Import(SecurityConfig.class)
class BlockControllerPlatformRoleTest {

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
    @MockitoBean BlockService blocks;

    private static Collection<GrantedAuthority> authorities(String... names) {
        List<GrantedAuthority> out = new ArrayList<>();
        for (String n : names) out.add(new SimpleGrantedAuthority(n));
        return out;
    }

    // ── matrix ──────────────────────────────────────────────────────────────

    @Test
    void matrixBlock_withoutRoleMatrix_isForbidden_serviceNeverCalled() {
        client.mutateWith(mockJwt().authorities(authorities("ROLE_USER")))
                .post().uri("/bff/user/blocks")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(Map.of("target", "@spammer:evil", "platform", "matrix"))
                .exchange()
                .expectStatus().isForbidden();
        verify(blocks, never()).block(anyString(), anyString(), anyString(), any(), any());
    }

    @Test
    void matrixBlock_withRoleMatrix_reachesService() {
        when(blocks.block(eq("alice"), eq("@ok:host"), eq("matrix"), any(), any()))
                .thenReturn(Mono.just(Map.of("pushed", false)));
        client.mutateWith(mockJwt().jwt(j -> j.subject("alice"))
                        .authorities(authorities("ROLE_USER", "ROLE_MATRIX")))
                .post().uri("/bff/user/blocks")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(Map.of("target", "@ok:host", "platform", "matrix"))
                .exchange()
                .expectStatus().isOk();
    }

    // ── mastodon ────────────────────────────────────────────────────────────

    @Test
    void mastodonBlock_withoutRoleMastodon_isForbidden_serviceNeverCalled() {
        client.mutateWith(mockJwt().authorities(authorities("ROLE_USER", "ROLE_MATRIX")))
                .post().uri("/bff/user/blocks")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(Map.of("target", "@spammer@evil", "platform", "mastodon"))
                .exchange()
                .expectStatus().isForbidden();
        verify(blocks, never()).block(anyString(), anyString(), anyString(), any(), any());
    }

    @Test
    void mastodonBlock_withRoleMastodon_reachesService() {
        when(blocks.block(eq("bob"), eq("@ok@host"), eq("mastodon"), any(), any()))
                .thenReturn(Mono.just(Map.of("pushed", false)));
        client.mutateWith(mockJwt().jwt(j -> j.subject("bob"))
                        .authorities(authorities("ROLE_USER", "ROLE_MASTODON")))
                .post().uri("/bff/user/blocks")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(Map.of("target", "@ok@host", "platform", "mastodon"))
                .exchange()
                .expectStatus().isOk();
    }

    // ── internal needs only the floor ────────────────────────────────────────

    @Test
    void internalBlock_needsOnlyRoleUserFloor() {
        when(blocks.block(eq("alice"), eq("someone"), eq("internal"), any(), any()))
                .thenReturn(Mono.just(Map.of("pushed", false)));
        client.mutateWith(mockJwt().jwt(j -> j.subject("alice")).authorities(authorities("ROLE_USER")))
                .post().uri("/bff/user/blocks")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(Map.of("target", "someone", "platform", "internal"))
                .exchange()
                .expectStatus().isOk();
    }

    // ── recommend-instance-block needs a platform role ───────────────────────

    @Test
    void recommendInstanceBlock_withoutPlatformRole_isForbidden() {
        client.mutateWith(mockJwt().authorities(authorities("ROLE_USER")))
                .post().uri("/bff/user/recommend-instance-block")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(Map.of("instance", "evil.example", "reason", "spam"))
                .exchange()
                .expectStatus().isForbidden();
        verify(blocks, never()).recommendInstanceBlock(anyString(), anyString(), anyString(), any());
    }

    @Test
    void recommendInstanceBlock_withPlatformRole_reachesService() {
        when(blocks.recommendInstanceBlock(eq("alice"), eq("evil.example"), any(), any()))
                .thenReturn(Mono.just(Map.of("recommended", true)));
        client.mutateWith(mockJwt().jwt(j -> j.subject("alice"))
                        .authorities(authorities("ROLE_USER", "ROLE_MASTODON")))
                .post().uri("/bff/user/recommend-instance-block")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(Map.of("instance", "evil.example", "reason", "spam"))
                .exchange()
                .expectStatus().isOk();
    }

    /** Kept for symmetry with the service-leg set used elsewhere. */
    @SuppressWarnings("unused")
    private static final Set<String> PLATFORM_ROLES = Set.of("ROLE_USER", "ROLE_MATRIX", "ROLE_MASTODON");
}
