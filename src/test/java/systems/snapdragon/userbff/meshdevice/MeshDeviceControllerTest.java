package systems.snapdragon.userbff.meshdevice;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webflux.test.autoconfigure.WebFluxTest;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpStatus;
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
import java.util.HashMap;
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
 * Slice test for {@link MeshDeviceController} via {@link WebTestClient}. Imports the
 * real {@link SecurityConfig} so the {@code /bff/user/**} ROLE_USER floor + the
 * {@code @PreAuthorize("hasRole('USER')")} method gate are exercised; the
 * {@link MeshDeviceService} is mocked. Proves: the owner is ALWAYS the JWT subject
 * (never a body field); claim accepts the pre-normalization shapes and surfaces the
 * service's 409 on a duplicate; a malformed node id is a clean 400 BEFORE the service;
 * visibility PUT happy/400/404/409 paths; release maps to 204/404; and the USER floor
 * (anonymous → 401, a non-USER authenticated principal → 403).
 */
@WebFluxTest(controllers = MeshDeviceController.class)
@Import(SecurityConfig.class)
@EnableReactiveMethodSecurity
class MeshDeviceControllerTest {

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
    @MockitoBean MeshDeviceService service;

    private static Collection<GrantedAuthority> authorities(String... names) {
        List<GrantedAuthority> out = new ArrayList<>();
        for (String n : names) out.add(new SimpleGrantedAuthority(n));
        return out;
    }

    private static MeshDevice device(String id, String nodeId, String visibility, String state) {
        return new MeshDevice(id, nodeId, "field radio", visibility, state,
                null, null, null, null, null, null, null, Instant.now());
    }

    /** A claim body; {@code label} nullable (omitted from the JSON when null). */
    private static Map<String, Object> claimBody(String nodeId, String label) {
        Map<String, Object> b = new HashMap<>();
        b.put("nodeId", nodeId);
        if (label != null) b.put("label", label);
        return b;
    }

    // ── list ────────────────────────────────────────────────

    @Test
    void listMine_authenticated_returnsMyDevices() {
        when(service.listMine(eq("alice"), any())).thenReturn(Flux.just(
                device("d1", "!a1b2c3d4", "private", "active"),
                device("d2", "!b2c3d4e5", "friends", "revoked")));

        client.mutateWith(mockJwt().jwt(j -> j.subject("alice")).authorities(authorities("ROLE_USER")))
                .get().uri("/bff/user/mesh-devices")
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.length()").isEqualTo(2)
                .jsonPath("$[0].nodeId").isEqualTo("!a1b2c3d4")
                .jsonPath("$[0].visibility").isEqualTo("private")
                // a revoked row is still listed to its owner (state visible).
                .jsonPath("$[1].state").isEqualTo("revoked");

        verify(service).listMine(eq("alice"), any());
    }

    @Test
    void listMine_anonymous_isUnauthorized() {
        client.get().uri("/bff/user/mesh-devices").exchange().expectStatus().isUnauthorized();
        verify(service, never()).listMine(anyString(), any());
    }

    // ── claim ───────────────────────────────────────────────

    @Test
    void claim_authenticatedUser_ownerIsJwtSubject_neverBody() {
        when(service.claim(eq("alice"), any(), eq("A1B2C3D4"), eq("field radio")))
                .thenReturn(Mono.just(device("d1", "!a1b2c3d4", "private", "active")));

        client.mutateWith(mockJwt().jwt(j -> j.subject("alice")).authorities(authorities("ROLE_USER")))
                .post().uri("/bff/user/mesh-devices")
                .contentType(MediaType.APPLICATION_JSON)
                // bare-uppercase accepted pre-normalization shape; the service stores canonical.
                .bodyValue(claimBody("A1B2C3D4", "field radio"))
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.id").isEqualTo("d1")
                .jsonPath("$.nodeId").isEqualTo("!a1b2c3d4")
                .jsonPath("$.visibility").isEqualTo("private")
                .jsonPath("$.state").isEqualTo("active");

        // owner is the JWT subject, never the body.
        verify(service).claim(eq("alice"), any(), eq("A1B2C3D4"), eq("field radio"));
    }

    @Test
    void claim_duplicateNodeId_surfacesAs409() {
        when(service.claim(eq("alice"), any(), eq("!a1b2c3d4"), any()))
                .thenReturn(Mono.error(ApiException.conflict(
                        "mesh node id !a1b2c3d4 is already registered on this platform")));

        client.mutateWith(mockJwt().jwt(j -> j.subject("alice")).authorities(authorities("ROLE_USER")))
                .post().uri("/bff/user/mesh-devices")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(claimBody("!a1b2c3d4", null))
                .exchange()
                .expectStatus().isEqualTo(HttpStatus.CONFLICT)
                .expectBody()
                .jsonPath("$.error").exists();
    }

    @Test
    void claim_malformedNodeId_isBadRequest_serviceNeverReached() {
        // not hex / wrong length / doubled prefix — all stopped by the @Pattern (400).
        for (String bad : new String[] {"not-a-node", "!a1b2c3d", "a1b2c3d4e", "!!a1b2c3d4"}) {
            client.mutateWith(mockJwt().jwt(j -> j.subject("alice")).authorities(authorities("ROLE_USER")))
                    .post().uri("/bff/user/mesh-devices")
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(claimBody(bad, null))
                    .exchange()
                    .expectStatus().isBadRequest();
        }
        verify(service, never()).claim(anyString(), any(), anyString(), any());
    }

    @Test
    void claim_missingNodeId_isBadRequest() {
        client.mutateWith(mockJwt().jwt(j -> j.subject("alice")).authorities(authorities("ROLE_USER")))
                .post().uri("/bff/user/mesh-devices")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(Map.of("label", "no node id"))
                .exchange()
                .expectStatus().isBadRequest();
        verify(service, never()).claim(anyString(), any(), anyString(), any());
    }

    @Test
    void claim_anonymous_isUnauthorized() {
        client.post().uri("/bff/user/mesh-devices")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(claimBody("!a1b2c3d4", null))
                .exchange()
                .expectStatus().isUnauthorized();
        verify(service, never()).claim(anyString(), any(), anyString(), any());
    }

    @Test
    void claim_authenticatedNonUser_isForbidden() {
        // an authenticated principal WITHOUT ROLE_USER hits the @PreAuthorize gate → 403.
        client.mutateWith(mockJwt().jwt(j -> j.subject("eve")).authorities(authorities("ROLE_GUEST")))
                .post().uri("/bff/user/mesh-devices")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(claimBody("!a1b2c3d4", null))
                .exchange()
                .expectStatus().isForbidden();
        verify(service, never()).claim(anyString(), any(), anyString(), any());
    }

    // ── visibility ──────────────────────────────────────────

    @Nested
    class Visibility {

        @Test
        void setVisibility_happyPath() {
            when(service.setVisibility(eq("alice"), eq("d1"), any(), eq("friends")))
                    .thenReturn(Mono.just(device("d1", "!a1b2c3d4", "friends", "active")));

            client.mutateWith(mockJwt().jwt(j -> j.subject("alice")).authorities(authorities("ROLE_USER")))
                    .put().uri("/bff/user/mesh-devices/d1/visibility")
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(Map.of("visibility", "friends"))
                    .exchange()
                    .expectStatus().isOk()
                    .expectBody()
                    .jsonPath("$.visibility").isEqualTo("friends");

            verify(service).setVisibility(eq("alice"), eq("d1"), any(), eq("friends"));
        }

        @Test
        void setVisibility_badValue_isBadRequest_serviceNeverReached() {
            client.mutateWith(mockJwt().jwt(j -> j.subject("alice")).authorities(authorities("ROLE_USER")))
                    .put().uri("/bff/user/mesh-devices/d1/visibility")
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(Map.of("visibility", "everyone"))
                    .exchange()
                    .expectStatus().isBadRequest();
            verify(service, never()).setVisibility(anyString(), anyString(), any(), anyString());
        }

        @Test
        void setVisibility_foreignOrUnknownId_is404_noExistenceLeak() {
            when(service.setVisibility(eq("alice"), eq("someone-elses"), any(), eq("friends")))
                    .thenReturn(Mono.error(ApiException.notFound("no such mesh device for this user")));

            client.mutateWith(mockJwt().jwt(j -> j.subject("alice")).authorities(authorities("ROLE_USER")))
                    .put().uri("/bff/user/mesh-devices/someone-elses/visibility")
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(Map.of("visibility", "friends"))
                    .exchange()
                    .expectStatus().isNotFound();
        }

        @Test
        void setVisibility_revokedDevice_is409() {
            when(service.setVisibility(eq("alice"), eq("d1"), any(), eq("channels")))
                    .thenReturn(Mono.error(ApiException.conflict(
                            "mesh device is revoked — visibility cannot be changed")));

            client.mutateWith(mockJwt().jwt(j -> j.subject("alice")).authorities(authorities("ROLE_USER")))
                    .put().uri("/bff/user/mesh-devices/d1/visibility")
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(Map.of("visibility", "channels"))
                    .exchange()
                    .expectStatus().isEqualTo(HttpStatus.CONFLICT);
        }

        @Test
        void setVisibility_anonymous_isUnauthorized() {
            client.put().uri("/bff/user/mesh-devices/d1/visibility")
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(Map.of("visibility", "friends"))
                    .exchange()
                    .expectStatus().isUnauthorized();
            verify(service, never()).setVisibility(anyString(), anyString(), any(), anyString());
        }
    }

    // ── release ─────────────────────────────────────────────

    @Test
    void release_mine_isNoContent() {
        when(service.release(eq("alice"), eq("d1"), any())).thenReturn(Mono.empty());

        client.mutateWith(mockJwt().jwt(j -> j.subject("alice")).authorities(authorities("ROLE_USER")))
                .delete().uri("/bff/user/mesh-devices/d1")
                .exchange()
                .expectStatus().isNoContent();

        verify(service).release(eq("alice"), eq("d1"), any());
    }

    @Test
    void release_foreignOrUnknownId_is404_notForbidden() {
        // the service deletes ZERO rows for a foreign id → 404 (no cross-owner
        // existence leak), never a 403.
        when(service.release(eq("alice"), eq("someone-elses"), any()))
                .thenReturn(Mono.error(ApiException.notFound("no such mesh device for this user")));

        client.mutateWith(mockJwt().jwt(j -> j.subject("alice")).authorities(authorities("ROLE_USER")))
                .delete().uri("/bff/user/mesh-devices/someone-elses")
                .exchange()
                .expectStatus().isNotFound();
    }

    @Test
    void release_anonymous_isUnauthorized() {
        client.delete().uri("/bff/user/mesh-devices/d1").exchange().expectStatus().isUnauthorized();
        verify(service, never()).release(anyString(), anyString(), any());
    }
}
