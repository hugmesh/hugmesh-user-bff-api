package net.hugmesh.userbff.character;

import org.junit.jupiter.api.BeforeEach;
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
import net.hugmesh.userbff.security.PrincipalDomain;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * Slice test for {@link CharacterAvatarController} — the ROUTE hugmesh-forum-bff-api
 * issue #3 was filed for. The forum VN editor stored the literal path
 * {@code /bff/user/character/avatar} in a VN profile while this BFF served NOTHING at
 * any avatar path a reader could resolve, so every avatar-mode sprite rendered broken.
 *
 * <p><b>This class is the regression that fails when the route is absent</b>: delete
 * (or re-path) {@link CharacterAvatarController} and {@link #handleRoute_exists} /
 * {@link #bodyRoute_exists_andServesTheStoredPixels} stop seeing 200s — a missing
 * @RestController falls through the {@code /bff/user/**} authenticated floor to a 404
 * for an authenticated caller, which is precisely the defect a reader's browser saw.
 *
 * <p>Also pinned here: the handle route's 404-when-I-have-no-picture (the UI
 * feature-detect), the UNIFORM 404 on every body-route miss (a malformed handle is
 * rejected before the service ever runs, so a well-formed miss cannot be told apart
 * from a malformed one), the hardened image headers, and the ROLE_USER floor
 * (anonymous → 401, non-USER → 403). {@link SecurityConfig} is the REAL one.
 */
@WebFluxTest(controllers = CharacterAvatarController.class)
@Import(SecurityConfig.class)
@EnableReactiveMethodSecurity
class CharacterAvatarControllerTest {

    /** A well-formed handle (lowercase-hex UUID) — the shape the controller gates on. */
    private static final String REF = "3f2504e0-4f89-41d3-9a0c-0305e82c3301";

    /** The canonical URL the forum VN profile stores. Byte-for-byte the contract
     *  hugmesh-forum-ui mirrors in {@code character-avatar.ts}. */
    private static final String BODY_URL = "/bff/user/character/avatar/" + REF + "/body";

    private static final byte[] PNG = {(byte) 0x89, 'P', 'N', 'G', 13, 10, 26, 10, 1, 2, 3, 4};

    @Autowired ApplicationContext context;
    WebTestClient client;

    @BeforeEach
    void setUpSecuredWebTestClient() {
        client = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    @MockitoBean ReactiveJwtDecoder jwtDecoder;
    @MockitoBean CharacterAvatarService service;
    @MockitoBean PrincipalDomain principalDomain;

    private static Collection<GrantedAuthority> authorities(String... names) {
        List<GrantedAuthority> out = new ArrayList<>();
        for (String n : names) out.add(new SimpleGrantedAuthority(n));
        return out;
    }

    private WebTestClient asUser(String subject) {
        return client.mutateWith(mockJwt().jwt(j -> j.subject(subject)).authorities(authorities("ROLE_USER")));
    }

    // ── GET /bff/user/character/avatar (my handle) ──────────

    @Test
    void handleRoute_exists() {
        when(principalDomain.forScope(any())).thenReturn("default");
        when(service.refForOwner(eq("alice"), eq("default"))).thenReturn(Mono.just(REF));

        asUser("alice").get().uri("/bff/user/character/avatar")
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.ref").isEqualTo(REF)
                // The server owns the URL spelling; the UI stores exactly what it is told.
                .jsonPath("$.url").isEqualTo(BODY_URL);

        // owner = the JWT subject, never a request field.
        verify(service).refForOwner(eq("alice"), eq("default"));
    }

    @Test
    void handleRoute_noStoredPicture_is404_soTheUiCanFeatureDetect() {
        when(principalDomain.forScope(any())).thenReturn("default");
        when(service.refForOwner(anyString(), any())).thenReturn(Mono.empty());

        asUser("alice").get().uri("/bff/user/character/avatar")
                .exchange()
                .expectStatus().isNotFound();
    }

    @Test
    void handleRoute_anonymous_isUnauthorized() {
        client.get().uri("/bff/user/character/avatar").exchange().expectStatus().isUnauthorized();
        verify(service, never()).refForOwner(anyString(), any());
    }

    @Test
    void handleRoute_authenticatedNonUser_isForbidden() {
        client.mutateWith(mockJwt().jwt(j -> j.subject("eve")).authorities(authorities("ROLE_GUEST")))
                .get().uri("/bff/user/character/avatar")
                .exchange()
                .expectStatus().isForbidden();
        verify(service, never()).refForOwner(anyString(), any());
    }

    // ── GET /bff/user/character/avatar/{ref}/body (the sprite) ──

    @Test
    void bodyRoute_exists_andServesTheStoredPixels() {
        when(principalDomain.forScope(any())).thenReturn("default");
        when(service.serveBody(eq(REF), eq("bob"), eq("default")))
                .thenReturn(Mono.just(new CharacterAvatarService.AvatarBody(PNG, "image/png")));

        // bob is NOT the owner — a sprite has to render for the READERS of a post.
        byte[] got = asUser("bob").get().uri(BODY_URL)
                .exchange()
                .expectStatus().isOk()
                .expectHeader().contentType("image/png")
                .expectHeader().valueEquals("X-Content-Type-Options", "nosniff")
                .expectHeader().valueEquals("Content-Security-Policy", "default-src 'none'")
                .expectHeader().valueEquals("Content-Disposition", "inline")
                // STABLE handle + URL-keyed browser cache ⇒ a freshness window would keep
                // serving replaced or moderator-removed pixels to every reader.
                .expectHeader().cacheControl(org.springframework.http.CacheControl.noStore())
                .expectBody(byte[].class)
                .returnResult().getResponseBody();

        assertThat(got).isEqualTo(PNG);
    }

    @Test
    void bodyRoute_serviceMiss_isUniform404() {
        when(principalDomain.forScope(any())).thenReturn("default");
        when(service.serveBody(anyString(), anyString(), any())).thenReturn(Mono.empty());

        asUser("bob").get().uri(BODY_URL).exchange().expectStatus().isNotFound();
    }

    @Test
    void bodyRoute_malformedHandle_is404_beforeTheServiceRuns() {
        when(principalDomain.forScope(any())).thenReturn("default");

        // Not a UUID: an uppercase-hex variant, a bare word, a short digit run and a
        // sticker-style slug all land on the SAME 404 an unknown handle gets — a
        // well-formed miss must not be distinguishable from a malformed one.
        for (String bad : List.of("3F2504E0-4F89-41D3-9A0C-0305E82C3301", "avatar", "1234",
                "3f2504e04f8941d39a0c0305e82c3301", "3f2504e0-4f89-41d3-9a0c-0305e82c3301x")) {
            asUser("bob").get().uri("/bff/user/character/avatar/" + bad + "/body")
                    .exchange()
                    .expectStatus().isNotFound();
        }
        verify(service, never()).serveBody(anyString(), anyString(), any());
    }

    @Test
    void bodyRoute_traversalSegment_isRefusedBeforeTheApp() {
        when(principalDomain.forScope(any())).thenReturn("default");

        // A `..` segment never even reaches the handler — WebFlux rejects the suspicious
        // path itself (400). Asserted so a future move to a lenient path resolver shows
        // up here rather than as a silently-reachable traversal; either way the service
        // is not called and no bytes are served.
        asUser("bob").get().uri("/bff/user/character/avatar/../body")
                .exchange()
                .expectStatus().isBadRequest();

        verify(service, never()).serveBody(anyString(), anyString(), any());
    }

    @Test
    void bodyRoute_anonymous_isUnauthorized() {
        client.get().uri(BODY_URL).exchange().expectStatus().isUnauthorized();
        verify(service, never()).serveBody(anyString(), anyString(), any());
    }

    @Test
    void bodyRoute_authenticatedNonUser_isForbidden() {
        client.mutateWith(mockJwt().jwt(j -> j.subject("eve")).authorities(authorities("ROLE_GUEST")))
                .get().uri(BODY_URL)
                .exchange()
                .expectStatus().isForbidden();
        verify(service, never()).serveBody(anyString(), anyString(), any());
    }
}
