package net.hugmesh.userbff.profile;

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
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.reactive.function.BodyInserters;
import reactor.core.publisher.Mono;
import net.hugmesh.userbff.config.SecurityConfig;
import net.hugmesh.userbff.security.PrincipalDomain;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * HTTP-layer tests for the {@link ProfileController} avatar-upload endpoint
 * ({@code POST /bff/user/profile/avatar}). {@link AvatarService} + {@link ProfileService}
 * are mocked so these stay at the HTTP boundary:
 * <ul>
 *   <li>a valid image multipart → 200 returning the refreshed profile (with avatarUrl);
 *       the service is called with the JWT subject as owner;</li>
 *   <li>a non-image content-type → 400, and the avatar service is NEVER called;</li>
 *   <li>an oversize (&gt;5MB) image → 400, and the avatar service is NEVER called.</li>
 * </ul>
 */
@WebFluxTest(controllers = ProfileController.class)
@Import(SecurityConfig.class)
@TestPropertySource(properties = "spring.security.oauth2.resourceserver.jwt.issuer-uri=")
class ProfileControllerAvatarTest {

    @Autowired ApplicationContext context;
    WebTestClient client;

    @BeforeEach
    void setUpSecuredWebTestClient() {
        client = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    @MockitoBean ReactiveJwtDecoder jwtDecoder;
    @MockitoBean ProfileService profiles;
    @MockitoBean AvatarService avatars;
    @MockitoBean PrincipalDomain principalDomain;

    private static UserProfile withAvatar(String userId, String mxc) {
        return new UserProfile(userId, null, null, null, "Display", "internal", false, null, null, mxc);
    }

    /** A minimal byte buffer that begins with the PNG magic-byte signature (8-byte header
     *  + padding to clear ImageSniffer's 12-byte floor), so the server-side sniff detects
     *  it as a real image/png — the client header alone is no longer trusted. */
    private static byte[] pngBytes() {
        return new byte[]{
                (byte) 0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A, // PNG signature
                0, 0, 0, 0                                          // pad past the 12-byte floor
        };
    }

    /** A multipart body whose 'file' part carries the given bytes + content-type. */
    private static BodyInserters.MultipartInserter multipart(byte[] bytes, String contentType) {
        MultipartBodyBuilder b = new MultipartBodyBuilder();
        b.part("file", new ByteArrayResource(bytes) {
            @Override public String getFilename() { return "avatar"; }
        }).header(HttpHeaders.CONTENT_TYPE, contentType);
        return BodyInserters.fromMultipartData(b.build());
    }

    @Test
    void validImage_returnsRefreshedProfileWithAvatar() {
        when(principalDomain.forScope(any())).thenReturn("default");
        when(avatars.uploadAndStore(eq("alice"), any(), eq("image/png"), eq("default")))
                .thenReturn(Mono.just("mxc://home/abc"));
        when(profiles.get(eq("alice"), eq("default")))
                .thenReturn(Mono.just(withAvatar("alice", "mxc://home/abc")));

        client.mutateWith(mockJwt()
                        .jwt(j -> j.subject("alice"))
                        .authorities(new SimpleGrantedAuthority("ROLE_USER")))
                .post().uri("/bff/user/profile/avatar")
                .contentType(MediaType.MULTIPART_FORM_DATA)
                .body(multipart(pngBytes(), "image/png"))
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.userId").isEqualTo("alice")
                .jsonPath("$.avatarUrl").isEqualTo("mxc://home/abc");

        verify(avatars).uploadAndStore(eq("alice"), any(), eq("image/png"), eq("default"));
    }

    @Test
    void nonImageContentType_isBadRequest_noUpload() {
        when(principalDomain.forScope(any())).thenReturn("default");

        client.mutateWith(mockJwt()
                        .jwt(j -> j.subject("alice"))
                        .authorities(new SimpleGrantedAuthority("ROLE_USER")))
                .post().uri("/bff/user/profile/avatar")
                .contentType(MediaType.MULTIPART_FORM_DATA)
                .body(multipart("not an image".getBytes(), "text/plain"))
                .exchange()
                .expectStatus().isBadRequest();

        verify(avatars, never()).uploadAndStore(anyString(), any(), anyString(), any());
    }

    @Test
    void oversizeImage_isBadRequest_noUpload() {
        when(principalDomain.forScope(any())).thenReturn("default");
        // 6 MB > the 5 MB cap
        byte[] big = new byte[6 * 1024 * 1024];

        client.mutateWith(mockJwt()
                        .jwt(j -> j.subject("alice"))
                        .authorities(new SimpleGrantedAuthority("ROLE_USER")))
                .post().uri("/bff/user/profile/avatar")
                .contentType(MediaType.MULTIPART_FORM_DATA)
                .body(multipart(big, "image/png"))
                .exchange()
                .expectStatus().isBadRequest();

        verify(avatars, never()).uploadAndStore(anyString(), any(), anyString(), any());
    }

    @Test
    void svgLabeledImage_failsMagicByteCheck_isBadRequest_noUpload() {
        when(principalDomain.forScope(any())).thenReturn("default");
        // An SVG (XML/script vector) that LIES about being a raster image via the client
        // header. ImageSniffer deliberately does not recognise SVG, so the magic-byte gate
        // must reject it (stored-XSS defence) — 400, and nothing is ever stored.
        byte[] svg = "<svg xmlns=\"http://www.w3.org/2000/svg\"><script>alert(1)</script></svg>"
                .getBytes();

        client.mutateWith(mockJwt()
                        .jwt(j -> j.subject("alice"))
                        .authorities(new SimpleGrantedAuthority("ROLE_USER")))
                .post().uri("/bff/user/profile/avatar")
                .contentType(MediaType.MULTIPART_FORM_DATA)
                .body(multipart(svg, "image/svg+xml"))
                .exchange()
                .expectStatus().isBadRequest();

        verify(avatars, never()).uploadAndStore(anyString(), any(), anyString(), any());
    }

    @Test
    void htmlBytesLabeledPng_failsMagicByteCheck_isBadRequest_noUpload() {
        when(principalDomain.forScope(any())).thenReturn("default");
        // HTML bytes masquerading as image/png via the client header — the header passes
        // the cheap startsWith("image/") gate but the magic-byte sniff rejects it. 400, no store.
        byte[] html = "<html><body><script>alert('xss')</script></body></html>".getBytes();

        client.mutateWith(mockJwt()
                        .jwt(j -> j.subject("alice"))
                        .authorities(new SimpleGrantedAuthority("ROLE_USER")))
                .post().uri("/bff/user/profile/avatar")
                .contentType(MediaType.MULTIPART_FORM_DATA)
                .body(multipart(html, "image/png"))
                .exchange()
                .expectStatus().isBadRequest();

        verify(avatars, never()).uploadAndStore(anyString(), any(), anyString(), any());
    }

    @Test
    void anonymous_isUnauthorized() {
        client.post().uri("/bff/user/profile/avatar")
                .contentType(MediaType.MULTIPART_FORM_DATA)
                .body(multipart(new byte[]{1}, "image/png"))
                .exchange()
                .expectStatus().isUnauthorized();
        verify(avatars, never()).uploadAndStore(anyString(), any(), anyString(), any());
    }
}
