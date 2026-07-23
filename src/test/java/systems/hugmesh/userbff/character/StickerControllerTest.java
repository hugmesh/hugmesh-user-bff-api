package systems.hugmesh.userbff.character;

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
import systems.hugmesh.commons.web.ApiException;
import systems.hugmesh.userbff.config.SecurityConfig;
import systems.hugmesh.userbff.security.PrincipalDomain;

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
 * with NO service call; a moderation block surfaces as a 422; list returns my stickers;
 * the USER floor (anonymous → 401, a non-USER principal → 403).
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
}
