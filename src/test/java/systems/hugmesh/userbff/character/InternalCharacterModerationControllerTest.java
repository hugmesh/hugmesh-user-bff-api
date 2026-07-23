package systems.hugmesh.userbff.character;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
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
import reactor.core.publisher.Mono;
import systems.hugmesh.userbff.config.SecurityConfig;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * Slice test for {@link InternalCharacterModerationController} via {@link WebTestClient},
 * importing the REAL {@link SecurityConfig} so the {@code /bff/user/internal/**} route
 * gate AND the {@code @PreAuthorize("hasRole('SERVICE')")} method gate are exercised; the
 * {@link CharacterModerationService} is mocked. This is the CORE PRIVILEGE BOUNDARY test:
 * the endpoint flips a moderated row PENDING→ACTIVE/REJECTED, so a human reaching it could
 * ACTIVATE their own content without review — only the SERVICE principal may succeed.
 *
 * <ul>
 *   <li><b>SERVICE-ONLY GATE</b> — USER/ADMIN/MOD/SUPERADMIN are DENIED (403) and the
 *       service is NEVER reached; anonymous is 401; ONLY {@code ROLE_SERVICE} succeeds.</li>
 *   <li><b>FLIP CONTRACT</b> — a valid SERVICE call flips PENDING→ACTIVE/REJECTED and
 *       returns the post-flip row; an unknown / already-resolved id (service EMPTY) is a
 *       404 no-op; an invalid status is a 400 at the validation boundary. Parts +
 *       stickers behave identically.</li>
 * </ul>
 */
@WebFluxTest(controllers = InternalCharacterModerationController.class)
@Import(SecurityConfig.class)
@EnableReactiveMethodSecurity
class InternalCharacterModerationControllerTest {

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
    @MockitoBean CharacterModerationService service;

    private static final String PART_PATH = "/bff/user/internal/character/parts/p1/moderation";
    private static final String STICKER_PATH = "/bff/user/internal/character/stickers/s1/moderation";

    private static Collection<GrantedAuthority> authorities(String... names) {
        List<GrantedAuthority> out = new ArrayList<>();
        for (String n : names) out.add(new SimpleGrantedAuthority(n));
        return out;
    }

    private static Map<String, Object> resolveBody(String status) {
        Map<String, Object> b = new LinkedHashMap<>();
        b.put("status", status);
        b.put("findingId", 4242);
        b.put("reviewer", "mod-bob");
        return b;
    }

    private static VnCharacterPart part(String status) {
        return new VnCharacterPart("p1", "alice", "default", "ear", "<svg/>", status, "protogen", 4242L, Instant.now());
    }

    private static VnSticker sticker(String status) {
        return new VnSticker("s1", "alice", "default", "happy", "mxc://h/1", status, 4242L, Instant.now());
    }

    private static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.JwtMutator
            serviceJwt() {
        return mockJwt().jwt(j -> j.subject("hugmesh-actions")).authorities(authorities("ROLE_SERVICE"));
    }

    // ── SERVICE-ONLY GATE ─────────────────────────────────────────────────────
    @Nested
    class ServiceOnlyGate {

        @Test
        void servicePrincipal_flipsPartToActive() {
            when(service.resolvePart(eq("p1"), eq("ACTIVE"), eq(4242L), eq("mod-bob")))
                    .thenReturn(Mono.just(part("ACTIVE")));

            client.mutateWith(serviceJwt())
                    .post().uri(PART_PATH)
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(resolveBody("ACTIVE"))
                    .exchange()
                    .expectStatus().isOk()
                    .expectBody()
                    .jsonPath("$.id").isEqualTo("p1")
                    .jsonPath("$.status").isEqualTo("ACTIVE");

            verify(service).resolvePart(eq("p1"), eq("ACTIVE"), eq(4242L), eq("mod-bob"));
        }

        @Test
        void servicePrincipal_flipsStickerToRejected() {
            when(service.resolveSticker(eq("s1"), eq("REJECTED"), eq(4242L), eq("mod-bob")))
                    .thenReturn(Mono.just(sticker("REJECTED")));

            client.mutateWith(serviceJwt())
                    .post().uri(STICKER_PATH)
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(resolveBody("REJECTED"))
                    .exchange()
                    .expectStatus().isOk()
                    .expectBody()
                    .jsonPath("$.id").isEqualTo("s1")
                    .jsonPath("$.status").isEqualTo("REJECTED");
        }

        @Test
        void normalUser_isForbidden_serviceNeverReached() {
            client.mutateWith(mockJwt().jwt(j -> j.subject("mallory")).authorities(authorities("ROLE_USER")))
                    .post().uri(PART_PATH)
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(resolveBody("ACTIVE"))
                    .exchange()
                    .expectStatus().isForbidden();

            verify(service, never()).resolvePart(any(), any(), any(), any());
        }

        @Test
        void admin_isForbidden_serviceNeverReached() {
            client.mutateWith(mockJwt().jwt(j -> j.subject("an-admin"))
                            .authorities(authorities("ROLE_USER", "ROLE_ADMIN")))
                    .post().uri(PART_PATH)
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(resolveBody("ACTIVE"))
                    .exchange()
                    .expectStatus().isForbidden();

            verify(service, never()).resolvePart(any(), any(), any(), any());
        }

        @Test
        void mod_isForbidden_serviceNeverReached() {
            client.mutateWith(mockJwt().jwt(j -> j.subject("a-mod"))
                            .authorities(authorities("ROLE_USER", "ROLE_MOD")))
                    .post().uri(STICKER_PATH)
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(resolveBody("REJECTED"))
                    .exchange()
                    .expectStatus().isForbidden();

            verify(service, never()).resolveSticker(any(), any(), any(), any());
        }

        @Test
        void superadmin_isForbidden_serviceNeverReached() {
            // SUPERADMIN is the cross-domain super-role, but the role hierarchy has NO edge
            // to ROLE_SERVICE — so even SUPERADMIN cannot reach the flip path.
            client.mutateWith(mockJwt().jwt(j -> j.subject("a-superadmin"))
                            .authorities(authorities("ROLE_USER", "ROLE_SUPERADMIN")))
                    .post().uri(PART_PATH)
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(resolveBody("ACTIVE"))
                    .exchange()
                    .expectStatus().isForbidden();

            verify(service, never()).resolvePart(any(), any(), any(), any());
        }

        @Test
        void anonymous_isUnauthorized_serviceNeverReached() {
            client.post().uri(PART_PATH)
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(resolveBody("ACTIVE"))
                    .exchange()
                    .expectStatus().isUnauthorized();

            verify(service, never()).resolvePart(any(), any(), any(), any());
        }
    }

    // ── FLIP CONTRACT / VALIDATION ────────────────────────────────────────────
    @Nested
    class Contract {

        @Test
        void servicePrincipal_unknownOrAlreadyResolved_isNotFound_noOp() {
            // the service yields EMPTY for an unknown / already-resolved (non-PENDING) id;
            // the controller maps that to a 404 (nothing-flipped, idempotent no-op).
            when(service.resolvePart(eq("p1"), eq("ACTIVE"), any(), any())).thenReturn(Mono.empty());

            client.mutateWith(serviceJwt())
                    .post().uri(PART_PATH)
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(resolveBody("ACTIVE"))
                    .exchange()
                    .expectStatus().isNotFound();
        }

        @Test
        void servicePrincipal_stickerUnknown_isNotFound_noOp() {
            when(service.resolveSticker(eq("s1"), eq("ACTIVE"), any(), any())).thenReturn(Mono.empty());

            client.mutateWith(serviceJwt())
                    .post().uri(STICKER_PATH)
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(resolveBody("ACTIVE"))
                    .exchange()
                    .expectStatus().isNotFound();
        }

        @Test
        void servicePrincipal_invalidStatus_isBadRequest_serviceNotReached() {
            client.mutateWith(serviceJwt())
                    .post().uri(PART_PATH)
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(resolveBody("PENDING"))   // not a terminal status -> 400
                    .exchange()
                    .expectStatus().isBadRequest();

            verify(service, never()).resolvePart(any(), any(), any(), any());
        }

        @Test
        void servicePrincipal_blankStatus_isBadRequest_serviceNotReached() {
            Map<String, Object> bad = resolveBody("");
            client.mutateWith(serviceJwt())
                    .post().uri(STICKER_PATH)
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(bad)
                    .exchange()
                    .expectStatus().isBadRequest();

            verify(service, never()).resolveSticker(any(), any(), any(), any());
        }

        @Test
        void servicePrincipal_findingIdAndReviewerOptional() {
            // findingId + reviewer are audit-only; a body with just status still flips.
            when(service.resolvePart(eq("p1"), eq("ACTIVE"), eq(null), eq(null)))
                    .thenReturn(Mono.just(part("ACTIVE")));

            Map<String, Object> minimal = new LinkedHashMap<>();
            minimal.put("status", "ACTIVE");

            client.mutateWith(serviceJwt())
                    .post().uri(PART_PATH)
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(minimal)
                    .exchange()
                    .expectStatus().isOk();

            verify(service).resolvePart(eq("p1"), eq("ACTIVE"), eq(null), eq(null));
        }
    }
}
