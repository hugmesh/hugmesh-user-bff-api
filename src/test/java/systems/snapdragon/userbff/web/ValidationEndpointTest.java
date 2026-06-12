package systems.snapdragon.userbff.web;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.snapdragon.userbff.block.BlockService;
import systems.snapdragon.userbff.federation.FederationApiClient;
import systems.snapdragon.userbff.profile.ProfileService;
import systems.snapdragon.userbff.support.TestDatabaseConfig;

import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;

/**
 * END-TO-END validation coverage over the HTTP layer (the only layer where jakarta
 * Bean Validation + the reactive {@link ApiExceptionHandler} validation mappers
 * actually fire): a request that VIOLATES each newly-added constraint must come
 * back as a clean {@code 400} whose body names the offending field, AND the service
 * must NOT be invoked (validation short-circuits before the controller body). A
 * VALID request is accepted (existing behavior intact).
 *
 * <p>Full app context under the {@code test} profile (the real SecurityConfig
 * chain, the {@code ROLE_USER}-floored {@code /bff/user/**} surface) with the
 * services mocked; authenticates with a {@code mockJwt()} carrying {@code ROLE_USER}
 * so the assertion is the VALIDATION outcome, not an auth 401/403.
 */
@SpringBootTest
@AutoConfigureWebTestClient
@ActiveProfiles("test")
@Import(TestDatabaseConfig.class)
class ValidationEndpointTest {

    @Autowired WebTestClient web;

    /** No live Casdoor issuer — mock the decoder so oauth2 wiring is satisfied. */
    @MockitoBean ReactiveJwtDecoder reactiveJwtDecoder;

    @MockitoBean BlockService blockService;
    @MockitoBean ProfileService profileService;
    @MockitoBean FederationApiClient federationApiClient;

    private WebTestClient user() {
        return web.mutateWith(mockJwt().authorities(new SimpleGrantedAuthority("ROLE_USER")));
    }

    /** A principal that also holds the homeserver platform roles, so the
     *  BlockController platform-role @PreAuthorize gate passes and the assertion under
     *  test is the VALIDATION outcome (not a 403 from the role gate). */
    private WebTestClient platformUser() {
        return web.mutateWith(mockJwt().authorities(
                new SimpleGrantedAuthority("ROLE_USER"),
                new SimpleGrantedAuthority("ROLE_MATRIX"),
                new SimpleGrantedAuthority("ROLE_MASTODON")));
    }

    // ------------------------------------------------------------------
    // Block — @Valid BlockRequest (target required, platform enum) + {id} UUID
    // ------------------------------------------------------------------

    @Test
    void createBlock_missingTarget_is400_andNeverCallsService() {
        user().post().uri("/bff/user/blocks")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"platform\":\"matrix\"}")
                .exchange()
                .expectStatus().isBadRequest()
                .expectBody()
                .jsonPath("$.error").isEqualTo("validation failed")
                .jsonPath("$.fields.target").exists();
        verify(blockService, never()).block(any(), any(), any(), any(), any());
    }

    @Test
    void createBlock_badPlatform_is400() {
        user().post().uri("/bff/user/blocks")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"target\":\"@evil:host\",\"platform\":\"irc\"}")
                .exchange()
                .expectStatus().isBadRequest()
                .expectBody().jsonPath("$.fields.platform").exists();
        verify(blockService, never()).block(any(), any(), any(), any(), any());
    }

    @Test
    void createBlock_valid_is2xx() {
        when(blockService.block(any(), anyString(), any(), any(), any()))
                .thenReturn(Mono.just(Map.of("ok", true)));
        // matrix platform -> the @PreAuthorize gate needs ROLE_MATRIX (platformUser()).
        platformUser().post().uri("/bff/user/blocks")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"target\":\"@evil:host\",\"platform\":\"matrix\"}")
                .exchange()
                .expectStatus().is2xxSuccessful();
        verify(blockService).block(any(), anyString(), any(), any(), any());
    }

    @Test
    void deleteBlock_badId_is400_pathVariablePattern() {
        user().delete().uri("/bff/user/blocks/not-a-uuid")
                .exchange()
                .expectStatus().isBadRequest();
        verify(blockService, never()).unblock(any(), anyString());
    }

    @Test
    void recommendInstanceBlock_missingInstance_is400() {
        // platformUser() so the method-level platform-role @PreAuthorize passes and the
        // assertion is the @Valid (missing instance) outcome, not a 403 from the gate.
        platformUser().post().uri("/bff/user/recommend-instance-block")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"reason\":\"spam\"}")
                .exchange()
                .expectStatus().isBadRequest()
                .expectBody().jsonPath("$.fields.instance").exists();
        verify(blockService, never()).recommendInstanceBlock(any(), any(), any(), any());
    }

    // ------------------------------------------------------------------
    // Profile — @Valid UserProfile (visibility enum) + email/password DTOs
    // ------------------------------------------------------------------

    @Test
    void upsertProfile_badVisibility_is400() {
        user().put().uri("/bff/user/profile")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"visibility\":\"secret\"}")
                .exchange()
                .expectStatus().isBadRequest()
                .expectBody().jsonPath("$.fields.visibility").exists();
        verify(profileService, never()).save(anyString(), any(), any(), any());
    }

    @Test
    void upsertProfile_validVisibility_is2xx() {
        when(profileService.save(anyString(), any(), any(), any()))
                .thenReturn(Mono.empty());
        user().put().uri("/bff/user/profile")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"visibility\":\"public\",\"vanitySubdomainEnabled\":false}")
                .exchange()
                .expectStatus().is2xxSuccessful();
        verify(profileService).save(anyString(), any(), any(), any());
    }

    @Test
    void changeEmail_invalidEmail_is400() {
        user().post().uri("/bff/user/profile/email")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"email\":\"not-an-email\"}")
                .exchange()
                .expectStatus().isBadRequest()
                .expectBody().jsonPath("$.fields.email").exists();
        verify(profileService, never()).changeEmail(any(), any());
    }

    @Test
    void changePassword_missingNewPassword_is400() {
        user().post().uri("/bff/user/profile/password")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"oldPassword\":\"x\"}")
                .exchange()
                .expectStatus().isBadRequest()
                .expectBody().jsonPath("$.fields.newPassword").exists();
        verify(profileService, never()).changePassword(any(), any(), any());
    }

    @Test
    void changeEmail_valid_is2xx() {
        lenient().when(profileService.casdoorEnabled()).thenReturn(false);
        when(profileService.changeEmail(anyString(), anyString())).thenReturn(Mono.empty());
        user().post().uri("/bff/user/profile/email")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"email\":\"alice@example.com\"}")
                .exchange()
                .expectStatus().is2xxSuccessful();
        verify(profileService).changeEmail(anyString(), anyString());
    }

    // ------------------------------------------------------------------
    // Cards — {slug} path-variable pattern + visibility param
    // ------------------------------------------------------------------

    @Test
    void cardBySlug_badSlug_is400() {
        user().get().uri("/bff/user/cards/Bad_Slug!")
                .exchange()
                .expectStatus().isBadRequest();
        verify(federationApiClient, never()).listBySlug(anyString());
    }

    @Test
    void cardBySlug_validSlug_is2xx() {
        when(federationApiClient.listBySlug(anyString())).thenReturn(Flux.empty());
        user().get().uri("/bff/user/cards/my-card")
                .exchange()
                .expectStatus().is2xxSuccessful();
        verify(federationApiClient).listBySlug("my-card");
    }
}
