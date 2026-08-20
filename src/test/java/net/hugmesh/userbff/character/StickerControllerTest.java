package net.hugmesh.userbff.character;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webflux.test.autoconfigure.WebFluxTest;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Import;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.client.MultipartBodyBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.reactive.function.BodyInserters;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.commons.web.ApiException;
import net.hugmesh.userbff.config.SecurityConfig;
import net.hugmesh.userbff.security.PrincipalDomain;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
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
 * Slice test for {@link StickerController} via {@link WebTestClient}. Imports the real
 * {@link SecurityConfig} so the {@code /bff/user/**} ROLE_USER floor + the
 * {@code @PreAuthorize("hasRole('USER')")} method gate are exercised; the
 * {@link StickerService} is mocked. Proves: a valid PNG multipart → 200 PENDING (owner =
 * JWT subject, sniffed type forwarded); a non-image / SVG-labeled / oversize part → 400
 * with NO service call; a moderation block surfaces as a 422; list returns my stickers
 * (incl. the {@code slug}/{@code label} wire fields the forum-ui picker keys on);
 * the USER floor (anonymous → 401, a non-USER principal → 403); the {@code {slug}/body}
 * serve leg (stored bytes + sniffed type + hardened headers, uniform 404 on any miss,
 * malformed slug rejected before the service).
 */
@WebFluxTest(controllers = StickerController.class)
@Import(SecurityConfig.class)
@EnableReactiveMethodSecurity
class StickerControllerTest {

    @Autowired ApplicationContext context;
    WebTestClient client;

    @BeforeEach
    void setUpSecuredWebTestClient() {
        client = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    @MockitoBean ReactiveJwtDecoder jwtDecoder;
    @MockitoBean StickerService service;
    @MockitoBean PrincipalDomain principalDomain;

    private static Collection<GrantedAuthority> authorities(String... names) {
        List<GrantedAuthority> out = new ArrayList<>();
        for (String n : names) out.add(new SimpleGrantedAuthority(n));
        return out;
    }

    private static VnSticker sticker(String id, String owner, String expression) {
        return new VnSticker(id, owner, "default", expression, "mxc://home/" + id, "PENDING", null, Instant.now());
    }

    /** A minimal byte buffer that begins with the PNG magic-byte signature (8-byte header
     *  + padding to clear ImageSniffer's 12-byte floor), so the server-side sniff detects
     *  it as a real image/png. */
    private static byte[] pngBytes() {
        return new byte[]{
                (byte) 0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A, // PNG signature
                0, 0, 0, 0                                          // pad past the 12-byte floor
        };
    }

    /** A multipart body with a 'file' part (bytes + content-type) + an 'expression' part. */
    private static BodyInserters.MultipartInserter multipart(byte[] bytes, String contentType,
                                                             String expression) {
        MultipartBodyBuilder b = new MultipartBodyBuilder();
        b.part("file", new ByteArrayResource(bytes) {
            @Override public String getFilename() { return "sticker"; }
        }).header(HttpHeaders.CONTENT_TYPE, contentType);
        b.part("expression", expression);
        return BodyInserters.fromMultipartData(b.build());
    }

    // ── save ────────────────────────────────────────────────

    @Test
    void save_validPng_returnsPendingSticker() {
        when(principalDomain.forScope(any())).thenReturn("default");
        when(service.save(eq("alice"), eq("default"), eq("happy"), any(), eq("image/png")))
                .thenReturn(Mono.just(sticker("st-1", "alice", "happy")));

        client.mutateWith(mockJwt().jwt(j -> j.subject("alice")).authorities(authorities("ROLE_USER")))
                .post().uri("/bff/user/character/stickers")
                .contentType(MediaType.MULTIPART_FORM_DATA)
                .body(multipart(pngBytes(), "image/png", "happy"))
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.id").isEqualTo("st-1")
                .jsonPath("$.status").isEqualTo("PENDING")
                .jsonPath("$.expression").isEqualTo("happy");

        // owner is the JWT subject, the sniffed image/png is forwarded (NOT the client header).
        verify(service).save(eq("alice"), eq("default"), eq("happy"), any(), eq("image/png"));
    }

    @Test
    void save_moderationBlock_surfacesAs422() {
        when(principalDomain.forScope(any())).thenReturn("default");
        when(service.save(eq("alice"), any(), eq("happy"), any(), anyString()))
                .thenReturn(Mono.error(ApiException.unprocessable("character sticker blocked by content policy")));

        client.mutateWith(mockJwt().jwt(j -> j.subject("alice")).authorities(authorities("ROLE_USER")))
                .post().uri("/bff/user/character/stickers")
                .contentType(MediaType.MULTIPART_FORM_DATA)
                .body(multipart(pngBytes(), "image/png", "happy"))
                .exchange()
                .expectStatus().value(code -> org.assertj.core.api.Assertions.assertThat(code).isEqualTo(422));
    }

    @Test
    void save_nonImageContentType_isBadRequest_noService() {
        when(principalDomain.forScope(any())).thenReturn("default");

        client.mutateWith(mockJwt().jwt(j -> j.subject("alice")).authorities(authorities("ROLE_USER")))
                .post().uri("/bff/user/character/stickers")
                .contentType(MediaType.MULTIPART_FORM_DATA)
                .body(multipart("not an image".getBytes(), "text/plain", "happy"))
                .exchange()
                .expectStatus().isBadRequest();

        verify(service, never()).save(anyString(), any(), anyString(), any(), anyString());
    }

    @Test
    void save_svgLabeledImage_failsMagicByteCheck_isBadRequest_noService() {
        when(principalDomain.forScope(any())).thenReturn("default");
        // An SVG (XML/script vector) lying about being a raster via the client header.
        // ImageSniffer deliberately rejects SVG → 400 (stored-XSS defence), nothing stored.
        byte[] svg = "<svg xmlns=\"http://www.w3.org/2000/svg\"><script>alert(1)</script></svg>".getBytes();

        client.mutateWith(mockJwt().jwt(j -> j.subject("alice")).authorities(authorities("ROLE_USER")))
                .post().uri("/bff/user/character/stickers")
                .contentType(MediaType.MULTIPART_FORM_DATA)
                .body(multipart(svg, "image/svg+xml", "happy"))
                .exchange()
                .expectStatus().isBadRequest();

        verify(service, never()).save(anyString(), any(), anyString(), any(), anyString());
    }

    @Test
    void save_oversizeImage_isBadRequest_noService() {
        when(principalDomain.forScope(any())).thenReturn("default");
        byte[] big = new byte[2 * 1024 * 1024]; // 2 MB > the 1 MB cap

        client.mutateWith(mockJwt().jwt(j -> j.subject("alice")).authorities(authorities("ROLE_USER")))
                .post().uri("/bff/user/character/stickers")
                .contentType(MediaType.MULTIPART_FORM_DATA)
                .body(multipart(big, "image/png", "happy"))
                .exchange()
                .expectStatus().isBadRequest();

        verify(service, never()).save(anyString(), any(), anyString(), any(), anyString());
    }

    @Test
    void save_anonymous_isUnauthorized() {
        client.post().uri("/bff/user/character/stickers")
                .contentType(MediaType.MULTIPART_FORM_DATA)
                .body(multipart(pngBytes(), "image/png", "happy"))
                .exchange()
                .expectStatus().isUnauthorized();
        verify(service, never()).save(anyString(), any(), anyString(), any(), anyString());
    }

    @Test
    void save_authenticatedNonUser_isForbidden() {
        client.mutateWith(mockJwt().jwt(j -> j.subject("eve")).authorities(authorities("ROLE_GUEST")))
                .post().uri("/bff/user/character/stickers")
                .contentType(MediaType.MULTIPART_FORM_DATA)
                .body(multipart(pngBytes(), "image/png", "happy"))
                .exchange()
                .expectStatus().isForbidden();
        verify(service, never()).save(anyString(), any(), anyString(), any(), anyString());
    }

    // ── list ────────────────────────────────────────────────

    @Test
    void listMine_authenticated_returnsMyStickers() {
        when(principalDomain.forScope(any())).thenReturn("default");
        when(service.listMine(eq("alice"), eq("default")))
                .thenReturn(Flux.just(sticker("s1", "alice", "happy"), sticker("s2", "alice", "sad")));

        client.mutateWith(mockJwt().jwt(j -> j.subject("alice")).authorities(authorities("ROLE_USER")))
                .get().uri("/bff/user/character/stickers")
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.length()").isEqualTo(2)
                .jsonPath("$[0].id").isEqualTo("s1");

        // the owner is the JWT subject — list is scoped to the caller, never a request field.
        verify(service).listMine(eq("alice"), eq("default"));
    }

    @Test
    void listMine_anonymous_isUnauthorized() {
        client.get().uri("/bff/user/character/stickers").exchange().expectStatus().isUnauthorized();
        verify(service, never()).listMine(anyString(), any());
    }

    @Test
    void listMine_wireShape_carriesSlugAndLabel_theForumPickerContract() {
        // forum-ui's sticker normalizer DROPS any list item without a `slug` (and shows
        // `label`/`name` else the raw slug) — pin the two contract fields on the wire.
        when(principalDomain.forScope(any())).thenReturn("default");
        when(service.listMine(eq("alice"), eq("default")))
                .thenReturn(Flux.just(sticker("s1", "alice", "happy")));

        client.mutateWith(mockJwt().jwt(j -> j.subject("alice")).authorities(authorities("ROLE_USER")))
                .get().uri("/bff/user/character/stickers")
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$[0].slug").isEqualTo("s1")
                .jsonPath("$[0].label").isEqualTo("happy");
    }

    // ── body serve (GET /{slug}/body) ───────────────────────

    private static final byte[] SERVED = {(byte) 0x89, 'P', 'N', 'G', 7, 7};

    @Test
    void serveBody_known_returnsBytesWithSniffedTypeAndHardenedHeaders() {
        when(principalDomain.forScope(any())).thenReturn("default");
        when(service.serveBody(eq("st-1"), eq("bob"), eq("default")))
                .thenReturn(Mono.just(new StickerService.StickerBody(SERVED, "image/png")));

        client.mutateWith(mockJwt().jwt(j -> j.subject("bob")).authorities(authorities("ROLE_USER")))
                .get().uri("/bff/user/character/stickers/st-1/body")
                .exchange()
                .expectStatus().isOk()
                .expectHeader().contentType(MediaType.IMAGE_PNG)
                .expectHeader().valueEquals("X-Content-Type-Options", "nosniff")
                .expectHeader().valueEquals("Content-Security-Policy", "default-src 'none'")
                // REGRESSION GATE (operator 2026-08-19): the URL carries only the slug
                // while the body is resolved for the JWT subject, and the browser HTTP
                // cache is URL-keyed and cookie-blind — the private,max-age=300 this
                // route used to send kept serving the PREVIOUS user's pixels after a
                // sign-out/account switch until the cache was manually cleared.
                .expectHeader().valueEquals(HttpHeaders.CACHE_CONTROL, "no-store")
                .expectBody(byte[].class).isEqualTo(SERVED);

        // caller identity + domain come from the TOKEN (the service applies the gates).
        verify(service).serveBody(eq("st-1"), eq("bob"), eq("default"));
    }

    @Test
    void serveBody_nullRecordedType_fallsBackToImagePng() {
        when(principalDomain.forScope(any())).thenReturn("default");
        when(service.serveBody(eq("st-2"), eq("bob"), eq("default")))
                .thenReturn(Mono.just(new StickerService.StickerBody(SERVED, null)));

        client.mutateWith(mockJwt().jwt(j -> j.subject("bob")).authorities(authorities("ROLE_USER")))
                .get().uri("/bff/user/character/stickers/st-2/body")
                .exchange()
                .expectStatus().isOk()
                .expectHeader().contentType(MediaType.IMAGE_PNG);
    }

    @Test
    void serveBody_unknownOrDenied_isUniform404() {
        // the service's empty covers EVERY miss: unknown id, foreign PENDING, REJECTED,
        // cross-domain, legacy no-pixels row — one indistinguishable 404.
        when(principalDomain.forScope(any())).thenReturn("default");
        when(service.serveBody(eq("st-9"), eq("bob"), eq("default"))).thenReturn(Mono.empty());

        client.mutateWith(mockJwt().jwt(j -> j.subject("bob")).authorities(authorities("ROLE_USER")))
                .get().uri("/bff/user/character/stickers/st-9/body")
                .exchange()
                .expectStatus().isNotFound();
    }

    @Test
    void serveBody_malformedSlug_is404_withoutTouchingTheService() {
        when(principalDomain.forScope(any())).thenReturn("default");

        // uppercase breaks the [a-z0-9_-]{1,64} shape (the forum STICKER_SLUG_RE mirror).
        client.mutateWith(mockJwt().jwt(j -> j.subject("bob")).authorities(authorities("ROLE_USER")))
                .get().uri("/bff/user/character/stickers/NOT-a-Slug/body")
                .exchange()
                .expectStatus().isNotFound();

        verify(service, never()).serveBody(anyString(), anyString(), any());
    }

    @Test
    void serveBody_anonymous_isUnauthorized() {
        client.get().uri("/bff/user/character/stickers/st-1/body")
                .exchange()
                .expectStatus().isUnauthorized();
        verify(service, never()).serveBody(anyString(), anyString(), any());
    }
}
