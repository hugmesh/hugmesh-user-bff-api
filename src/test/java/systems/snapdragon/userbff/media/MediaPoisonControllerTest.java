package systems.snapdragon.userbff.media;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.boot.webflux.test.autoconfigure.WebFluxTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.http.client.MultipartBodyBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;
import systems.snapdragon.userbff.auth.AdminBffInternalClient;
import systems.snapdragon.userbff.config.SecurityConfig;
import systems.snapdragon.userbff.media.MediaPoisonService.UploadOutcome;
import systems.snapdragon.userbff.media.PoisonModels.Backend;
import systems.snapdragon.userbff.media.PoisonModels.Health;

import java.time.Instant;
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
 * Slice test for the {@link MediaPoisonController} via {@link WebTestClient}. Imports
 * the real {@link SecurityConfig} so the {@code /bff/user/**} ROLE_USER floor + the
 * {@code @PreAuthorize("hasRole('USER')")} method gate are exercised; the
 * {@link MediaPoisonService} is mocked. Proves: anonymous is 401; an authenticated
 * ROLE_USER can upload (multipart) and the response carries the homeserver body verbatim
 * PLUS the server-owned cloak block; capability + status route through the service.
 */
@WebFluxTest(controllers = MediaPoisonController.class)
@Import({SecurityConfig.class, MediaPoisonControllerTest.Props.class})
@EnableReactiveMethodSecurity
class MediaPoisonControllerTest {

    @TestConfiguration
    static class Props {
        @Bean MediaPoisoningProperties mediaPoisoningProperties() {
            MediaPoisoningProperties p = new MediaPoisoningProperties();
            p.setEnabled(true);
            p.setDefaultMode("glaze");
            return p;
        }
    }

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
    @MockitoBean MediaPoisonService service;
    // 291: the controller now resolves the PERSISTED per-platform localpart — claim-first, else an
    // internal admin-bff read — so the slice must provide this bean (mocked; the claim-path tests
    // never touch it, the resolution-fallback test stubs getAccount).
    @MockitoBean AdminBffInternalClient adminBff;

    private static Collection<GrantedAuthority> authorities(String... names) {
        List<GrantedAuthority> out = new ArrayList<>();
        for (String n : names) out.add(new SimpleGrantedAuthority(n));
        return out;
    }

    private static MultipartBodyBuilder multipart(String platform, String mode) {
        MultipartBodyBuilder mb = new MultipartBodyBuilder();
        mb.part("file", new byte[]{(byte) 0x89, 'P', 'N', 'G'})
                .filename("a.png").contentType(MediaType.IMAGE_PNG);
        mb.part("platform", platform);
        if (mode != null) mb.part("mode", mode);
        return mb;
    }

    // ── upload ──────────────────────────────────────────────

    @Test
    void upload_anonymous_isUnauthorized() {
        client.post().uri("/bff/user/media/upload")
                .contentType(MediaType.MULTIPART_FORM_DATA)
                .bodyValue(multipart("mastodon", "glaze").build())
                .exchange()
                .expectStatus().isUnauthorized();
        verify(service, never()).upload(any(), any(), any(), any(), any(), any(), any(), any());
    }

    @Test
    void upload_authenticatedUser_returnsHomeserverBodyPlusCloakBlock() {
        MediaPoisonDecision dec = new MediaPoisonDecision("dec-1", "alice", "mastodon",
                "media-77", "glaze", "protected", "cuda", Instant.now());
        when(service.upload(eq("alice"), eq("alice_ml"), eq("mastodon"), eq("glaze"), any(), anyString(), any(), any()))
                .thenReturn(Mono.just(new UploadOutcome(
                        Map.of("id", "media-77", "url", "/media/orig.png"), dec)));

        // Synthetic bff_ session JWT: the mastodon_localpart claim (291) is the persisted Mastodon
        // fold — the media leg mints under THIS, not the subject. Claim-path: adminBff untouched.
        client.mutateWith(mockJwt()
                        .jwt(j -> j.subject("alice").claim("mastodon_localpart", "alice_ml"))
                        .authorities(authorities("ROLE_USER")))
                .post().uri("/bff/user/media/upload")
                .contentType(MediaType.MULTIPART_FORM_DATA)
                .bodyValue(multipart("mastodon", "glaze").build())
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                // homeserver body returned verbatim (UI compose logic untouched) ...
                .jsonPath("$.id").isEqualTo("media-77")
                // ... PLUS the server-owned cloak block the badge reads.
                .jsonPath("$.cloak.status").isEqualTo("protected")
                .jsonPath("$.cloak.mode").isEqualTo("glaze")
                .jsonPath("$.cloak.backend").isEqualTo("cuda");

        // owner = subject; localpart = the PERSISTED Mastodon fold from the claim (not the subject).
        verify(service).upload(eq("alice"), eq("alice_ml"), eq("mastodon"), eq("glaze"), any(), eq("a.png"), any(), any());
        verify(adminBff, never()).getAccount(anyString());
    }

    @Test
    void upload_noClaim_resolvesPersistedMastodonLocalpartOverInternalApi() {
        // 291: a JWT WITHOUT the synthetic mastodon_localpart claim (a real Casdoor JWT) must NOT
        // fall back to the old preferred_username/subject derivation — it resolves the account and
        // mints under the PERSISTED, collision-checked Mastodon fold. Here the account's Matrix
        // localpart is "al.ice" but the persisted Mastodon fold is "al_ice"; the media leg must use
        // "al_ice", never a re-fold of the subject/preferred_username.
        when(adminBff.getAccount("google:alice@x.com")).thenReturn(Mono.just(new AdminBffInternalClient.AccountView(
                "google:alice@x.com", "google", "alice@x.com", true, List.of("ROLE_USER"), "al.ice", "al_ice")));
        MediaPoisonDecision dec = new MediaPoisonDecision("dec-2", "alice", "mastodon",
                "media-88", "glaze", "protected", "cuda", Instant.now());
        when(service.upload(eq("alice"), eq("al_ice"), eq("mastodon"), any(), any(), anyString(), any(), any()))
                .thenReturn(Mono.just(new UploadOutcome(Map.of("id", "media-88"), dec)));

        client.mutateWith(mockJwt()
                        .jwt(j -> j.subject("alice").claim("email", "alice@x.com"))
                        .authorities(authorities("ROLE_USER")))
                .post().uri("/bff/user/media/upload")
                .contentType(MediaType.MULTIPART_FORM_DATA)
                .bodyValue(multipart("mastodon", "glaze").build())
                .exchange()
                .expectStatus().isOk()
                .expectBody().jsonPath("$.id").isEqualTo("media-88");

        verify(service).upload(eq("alice"), eq("al_ice"), eq("mastodon"), any(), any(), eq("a.png"), any(), any());
    }

    // ── capability ──────────────────────────────────────────

    @Test
    void capability_anonymous_isUnauthorized() {
        client.get().uri("/bff/user/media/capability").exchange().expectStatus().isUnauthorized();
    }

    @Test
    void capability_authenticated_rendersHonestState() {
        when(service.capability())
                .thenReturn(Mono.just(new Health("none", List.of(), null)));

        client.mutateWith(mockJwt().authorities(authorities("ROLE_USER")))
                .get().uri("/bff/user/media/capability")
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.backend").isEqualTo("none")
                .jsonPath("$.available").isEqualTo(false)
                .jsonPath("$.defaultMode").isEqualTo("glaze");
    }

    @Test
    void capability_workerPresent_availableTrue() {
        when(service.capability())
                .thenReturn(Mono.just(new Health(Backend.CUDA.wire(), List.of("glaze"), 60)));

        client.mutateWith(mockJwt().authorities(authorities("ROLE_USER")))
                .get().uri("/bff/user/media/capability")
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.backend").isEqualTo("cuda")
                .jsonPath("$.available").isEqualTo(true);
    }

    // ── status ──────────────────────────────────────────────

    @Test
    void status_authenticated_delegatesToOwnerScopedLookup() {
        MediaPoisonDecision dec = new MediaPoisonDecision("dec-1", "alice", "mastodon",
                "media-77", "glaze", "protected", "cuda", Instant.now());
        when(service.status(eq("alice"), eq("media-77"), any())).thenReturn(Mono.just(dec));

        client.mutateWith(mockJwt().jwt(j -> j.subject("alice")).authorities(authorities("ROLE_USER")))
                .get().uri("/bff/user/media/status/media-77")
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.status").isEqualTo("protected");

        verify(service).status(eq("alice"), eq("media-77"), any());
    }

    @Test
    void status_anonymous_isUnauthorized() {
        client.get().uri("/bff/user/media/status/media-77").exchange().expectStatus().isUnauthorized();
        verify(service, never()).status(anyString(), anyString(), any());
    }
}
