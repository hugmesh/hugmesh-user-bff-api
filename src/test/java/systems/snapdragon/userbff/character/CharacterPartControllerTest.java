package systems.snapdragon.userbff.character;

import org.junit.jupiter.api.BeforeEach;
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
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.snapdragon.commons.web.ApiException;
import systems.snapdragon.userbff.config.SecurityConfig;

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
 * Slice test for {@link CharacterPartController} via {@link WebTestClient}. Imports the
 * real {@link SecurityConfig} so the {@code /bff/user/**} ROLE_USER floor + the
 * {@code @PreAuthorize("hasRole('USER')")} method gate are exercised; the
 * {@link CharacterPartService} is mocked. Proves: save returns PENDING; a malformed SVG
 * surfaces as a 422; list returns my parts; the serve path sets the hardened
 * CSP/content-type/nosniff/disposition headers; the USER floor (anonymous → 401, a
 * non-USER authenticated principal → 403); and a cross-owner serve is a 404 (the service
 * yields empty for a non-owner → ApiException.notFound), never a 403.
 */
@WebFluxTest(controllers = CharacterPartController.class)
@Import(SecurityConfig.class)
@EnableReactiveMethodSecurity
class CharacterPartControllerTest {

    @Autowired ApplicationContext context;
    WebTestClient client;

    // Spring Security 7: the mockJwt() reactive mutator only injects the SecurityContext
    // when springSecurity()'s MutatorFilter is in the chain. A @WebFluxTest-autowired
    // client lacks it (-> 401), so build the client from the context with springSecurity().
    @BeforeEach
    void setUpSecuredWebTestClient() {
        client = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    @MockitoBean ReactiveJwtDecoder jwtDecoder;
    @MockitoBean CharacterPartService service;

    private static Collection<GrantedAuthority> authorities(String... names) {
        List<GrantedAuthority> out = new ArrayList<>();
        for (String n : names) out.add(new SimpleGrantedAuthority(n));
        return out;
    }

    private static VnCharacterPart part(String id, String owner, String svg) {
        return new VnCharacterPart(id, owner, "default", "ear", svg, "PENDING", "protogen", Instant.now());
    }

    // ── save ────────────────────────────────────────────────

    @Test
    void save_authenticatedUser_returnsPendingPart() {
        when(service.savePart(eq("alice"), any(), eq("ear"), eq("protogen"), anyString()))
                .thenReturn(Mono.just(part("part-1", "alice", "<svg/>")));

        client.mutateWith(mockJwt().jwt(j -> j.subject("alice")).authorities(authorities("ROLE_USER")))
                .post().uri("/bff/user/character/parts")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(Map.of("name", "ear", "headArchetype", "protogen",
                        "svg", "<svg xmlns='http://www.w3.org/2000/svg'><path d='M0 0 L1 1'/></svg>"))
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.id").isEqualTo("part-1")
                .jsonPath("$.status").isEqualTo("PENDING");

        // owner is the JWT subject, never the body.
        verify(service).savePart(eq("alice"), any(), eq("ear"), eq("protogen"), anyString());
    }

    @Test
    void save_malformedSvg_surfacesAs422() {
        when(service.savePart(eq("alice"), any(), any(), any(), anyString()))
                .thenReturn(Mono.error(ApiException.unprocessable("character part is not a valid SVG")));

        client.mutateWith(mockJwt().jwt(j -> j.subject("alice")).authorities(authorities("ROLE_USER")))
                .post().uri("/bff/user/character/parts")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(Map.of("svg", "<svg><path d='M0 0'"))
                .exchange()
                // 422 — the status was renamed UNPROCESSABLE_ENTITY -> UNPROCESSABLE_CONTENT
                // across Spring versions, so assert on the raw code, not the enum constant.
                .expectStatus().value(code -> org.assertj.core.api.Assertions.assertThat(code).isEqualTo(422));
    }

    @Test
    void save_blankSvg_isRejectedByBeanValidation_400() {
        // @NotBlank svg → a 400 before the service is touched.
        client.mutateWith(mockJwt().jwt(j -> j.subject("alice")).authorities(authorities("ROLE_USER")))
                .post().uri("/bff/user/character/parts")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(Map.of("name", "ear"))
                .exchange()
                .expectStatus().isBadRequest();
        verify(service, never()).savePart(anyString(), any(), any(), any(), anyString());
    }

    @Test
    void save_anonymous_isUnauthorized() {
        client.post().uri("/bff/user/character/parts")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(Map.of("svg", "<svg/>"))
                .exchange()
                .expectStatus().isUnauthorized();
        verify(service, never()).savePart(anyString(), any(), any(), any(), anyString());
    }

    @Test
    void save_authenticatedNonUser_isForbidden() {
        // an authenticated principal WITHOUT ROLE_USER hits the @PreAuthorize gate → 403.
        client.mutateWith(mockJwt().jwt(j -> j.subject("eve")).authorities(authorities("ROLE_GUEST")))
                .post().uri("/bff/user/character/parts")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(Map.of("svg", "<svg/>"))
                .exchange()
                .expectStatus().isForbidden();
        verify(service, never()).savePart(anyString(), any(), any(), any(), anyString());
    }

    // ── list ────────────────────────────────────────────────

    @Test
    void listMine_authenticated_returnsMyParts() {
        when(service.listMine(eq("alice"), any()))
                .thenReturn(Flux.just(part("p1", "alice", "<svg/>"), part("p2", "alice", "<svg/>")));

        client.mutateWith(mockJwt().jwt(j -> j.subject("alice")).authorities(authorities("ROLE_USER")))
                .get().uri("/bff/user/character/parts")
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.length()").isEqualTo(2)
                .jsonPath("$[0].id").isEqualTo("p1");

        verify(service).listMine(eq("alice"), any());
    }

    @Test
    void listMine_anonymous_isUnauthorized() {
        client.get().uri("/bff/user/character/parts").exchange().expectStatus().isUnauthorized();
        verify(service, never()).listMine(anyString(), any());
    }

    // ── serve svg ───────────────────────────────────────────

    @Test
    void serveSvg_authenticatedOwner_servesSanitizedSvgWithHardenedHeaders() {
        String svg = "<svg xmlns=\"http://www.w3.org/2000/svg\"><path d=\"M0 0 L1 1\"/></svg>";
        when(service.getOwned(eq("part-1"), eq("alice"))).thenReturn(Mono.just(part("part-1", "alice", svg)));

        client.mutateWith(mockJwt().jwt(j -> j.subject("alice")).authorities(authorities("ROLE_USER")))
                .get().uri("/bff/user/character/parts/part-1/svg")
                .exchange()
                .expectStatus().isOk()
                .expectHeader().contentType(MediaType.valueOf("image/svg+xml"))
                .expectHeader().valueEquals("Content-Security-Policy",
                        "default-src 'none'; style-src 'unsafe-inline'; sandbox")
                .expectHeader().valueEquals("X-Content-Type-Options", "nosniff")
                .expectHeader().valueEquals("Content-Disposition", "inline")
                .expectBody(String.class).isEqualTo(svg);

        verify(service).getOwned(eq("part-1"), eq("alice"));
    }

    @Test
    void serveSvg_crossOwner_is404_notForbidden() {
        // the service yields empty for a part that is not the caller's → 404 (no
        // cross-owner existence leak), mapped from ApiException.notFound.
        when(service.getOwned(eq("someone-elses"), eq("alice"))).thenReturn(Mono.empty());

        client.mutateWith(mockJwt().jwt(j -> j.subject("alice")).authorities(authorities("ROLE_USER")))
                .get().uri("/bff/user/character/parts/someone-elses/svg")
                .exchange()
                .expectStatus().isNotFound();

        verify(service).getOwned(eq("someone-elses"), eq("alice"));
    }

    @Test
    void serveSvg_anonymous_isUnauthorized() {
        client.get().uri("/bff/user/character/parts/part-1/svg").exchange().expectStatus().isUnauthorized();
        verify(service, never()).getOwned(anyString(), anyString());
    }
}
