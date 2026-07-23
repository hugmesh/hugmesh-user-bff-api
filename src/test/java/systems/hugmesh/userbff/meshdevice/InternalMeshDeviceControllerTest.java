package systems.hugmesh.userbff.meshdevice;

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
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.hugmesh.userbff.auth.AdminBffInternalClient;
import systems.hugmesh.userbff.auth.AdminBffInternalClient.AccountView;
import systems.hugmesh.userbff.config.SecurityConfig;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * Slice test for {@link InternalMeshDeviceController} via {@link WebTestClient},
 * importing the REAL {@link SecurityConfig} so the {@code /bff/user/internal/**} route
 * gate AND the {@code @PreAuthorize("hasRole('SERVICE')")} method gate are exercised;
 * the repository, service and admin-bff client are mocked. This is the CORE PRIVILEGE
 * BOUNDARY test: the mapping pairs radio node ids with Matrix localparts across every
 * owner (data no human JWT may read here), and the status leg mutates other users'
 * rows — only the SERVICE principal may succeed.
 *
 * <ul>
 *   <li><b>SERVICE-ONLY GATE</b> — USER/ADMIN/MOD/SUPERADMIN are DENIED (403) and the
 *       collaborators are NEVER reached; anonymous is 401; ONLY {@code ROLE_SERVICE}
 *       succeeds — on BOTH the GET mapping and the POST status batch.</li>
 *   <li><b>MAPPING CONTRACT</b> — rows come out as {@code {nodeId, localpart,
 *       displayName, visibility}} with {@code displayName} = the localpart (AccountView
 *       carries no display name); the owner subject is resolved ONCE per owner
 *       (dedupe); a row whose localpart cannot be resolved (admin-bff error OR a blank
 *       persisted localpart) is OMITTED, fail-soft — the rest of the mapping
 *       survives.</li>
 *   <li><b>STATUS CONTRACT</b> — the batch aggregates the service's per-report
 *       booleans into {@code {updated, ignored}} (unknown-node fail-soft counted, never
 *       an error) and an empty batch is a clean zero/zero.</li>
 * </ul>
 */
@WebFluxTest(controllers = InternalMeshDeviceController.class)
@Import(SecurityConfig.class)
@EnableReactiveMethodSecurity
class InternalMeshDeviceControllerTest {

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
    @MockitoBean MeshDeviceRepository repo;
    @MockitoBean MeshDeviceService service;
    @MockitoBean AdminBffInternalClient adminBff;

    private static final String PATH = "/bff/user/internal/mesh-devices";
    private static final String STATUS_PATH = "/bff/user/internal/mesh-devices/status";

    private static final String ALICE = "google:alice@example.com";
    private static final String BOB = "discord:bob";

    private static Collection<GrantedAuthority> authorities(String... names) {
        List<GrantedAuthority> out = new ArrayList<>();
        for (String n : names) out.add(new SimpleGrantedAuthority(n));
        return out;
    }

    private static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.JwtMutator
            serviceJwt() {
        return mockJwt().jwt(j -> j.subject("hugmesh-mesh-bridge")).authorities(authorities("ROLE_SERVICE"));
    }

    private static MeshDeviceEntity row(String owner, String nodeId, String visibility) {
        return new MeshDeviceEntity("id-" + nodeId, owner, "default", nodeId, null,
                visibility, MeshDevice.STATE_ACTIVE, null, null, null,
                null, null, null, null, null, Instant.now());
    }

    private static AccountView account(String id, String localpart) {
        return new AccountView(id, "google", "x@example.com", true, List.of("user"), localpart, "");
    }

    // ── SERVICE-ONLY GATE ─────────────────────────────────────────────────────
    @Nested
    class ServiceOnlyGate {

        @Test
        void servicePrincipal_getsTheMapping() {
            when(repo.listActiveForBridge()).thenReturn(Flux.just(row(ALICE, "!a1b2c3d4", "private")));
            when(adminBff.getAccount(ALICE)).thenReturn(Mono.just(account(ALICE, "alice")));

            client.mutateWith(serviceJwt())
                    .get().uri(PATH)
                    .exchange()
                    .expectStatus().isOk()
                    .expectBody()
                    .jsonPath("$.length()").isEqualTo(1)
                    .jsonPath("$[0].nodeId").isEqualTo("!a1b2c3d4")
                    .jsonPath("$[0].localpart").isEqualTo("alice");
        }

        @Test
        void normalUser_isForbidden_nothingReached() {
            client.mutateWith(mockJwt().jwt(j -> j.subject("mallory")).authorities(authorities("ROLE_USER")))
                    .get().uri(PATH)
                    .exchange()
                    .expectStatus().isForbidden();

            verify(repo, never()).listActiveForBridge();
            verify(adminBff, never()).getAccount(anyString());
        }

        @Test
        void admin_isForbidden_nothingReached() {
            client.mutateWith(mockJwt().jwt(j -> j.subject("an-admin"))
                            .authorities(authorities("ROLE_USER", "ROLE_ADMIN")))
                    .get().uri(PATH)
                    .exchange()
                    .expectStatus().isForbidden();

            verify(repo, never()).listActiveForBridge();
        }

        @Test
        void mod_isForbidden_nothingReached() {
            client.mutateWith(mockJwt().jwt(j -> j.subject("a-mod"))
                            .authorities(authorities("ROLE_USER", "ROLE_MOD")))
                    .get().uri(PATH)
                    .exchange()
                    .expectStatus().isForbidden();

            verify(repo, never()).listActiveForBridge();
        }

        @Test
        void superadmin_isForbidden_nothingReached() {
            // SUPERADMIN is the cross-domain super-role, but the role hierarchy has NO
            // edge to ROLE_SERVICE — even SUPERADMIN cannot read the node↔identity map.
            client.mutateWith(mockJwt().jwt(j -> j.subject("a-superadmin"))
                            .authorities(authorities("ROLE_USER", "ROLE_SUPERADMIN")))
                    .get().uri(PATH)
                    .exchange()
                    .expectStatus().isForbidden();

            verify(repo, never()).listActiveForBridge();
        }

        @Test
        void anonymous_isUnauthorized_nothingReached() {
            client.get().uri(PATH).exchange().expectStatus().isUnauthorized();
            verify(repo, never()).listActiveForBridge();
        }

        @Test
        void statusBatch_normalUser_isForbidden_serviceNeverReached() {
            client.mutateWith(mockJwt().jwt(j -> j.subject("mallory")).authorities(authorities("ROLE_USER")))
                    .post().uri(STATUS_PATH)
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(List.of(Map.of("nodeId", "!a1b2c3d4")))
                    .exchange()
                    .expectStatus().isForbidden();

            verify(service, never()).applyStatus(any(), any(), any(), any(), any(), any());
        }

        @Test
        void statusBatch_superadmin_isForbidden_serviceNeverReached() {
            client.mutateWith(mockJwt().jwt(j -> j.subject("a-superadmin"))
                            .authorities(authorities("ROLE_USER", "ROLE_SUPERADMIN")))
                    .post().uri(STATUS_PATH)
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(List.of(Map.of("nodeId", "!a1b2c3d4")))
                    .exchange()
                    .expectStatus().isForbidden();

            verify(service, never()).applyStatus(any(), any(), any(), any(), any(), any());
        }

        @Test
        void statusBatch_anonymous_isUnauthorized() {
            client.post().uri(STATUS_PATH)
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(List.of(Map.of("nodeId", "!a1b2c3d4")))
                    .exchange()
                    .expectStatus().isUnauthorized();

            verify(service, never()).applyStatus(any(), any(), any(), any(), any(), any());
        }
    }

    // ── MAPPING CONTRACT ──────────────────────────────────────────────────────
    @Nested
    class MappingContract {

        @Test
        void mappingShape_displayNameIsLocalpart_visibilityCarried_ownerResolvedOnce() {
            // alice owns TWO radios (one localpart read must serve both rows — dedupe);
            // bob owns one. Row order (oldest first) is preserved.
            when(repo.listActiveForBridge()).thenReturn(Flux.just(
                    row(ALICE, "!a1b2c3d4", "private"),
                    row(ALICE, "!b2c3d4e5", "channels"),
                    row(BOB, "!c3d4e5f6", "friends")));
            when(adminBff.getAccount(ALICE)).thenReturn(Mono.just(account(ALICE, "alice")));
            when(adminBff.getAccount(BOB)).thenReturn(Mono.just(account(BOB, "bob")));

            client.mutateWith(serviceJwt())
                    .get().uri(PATH)
                    .exchange()
                    .expectStatus().isOk()
                    .expectBody()
                    .jsonPath("$.length()").isEqualTo(3)
                    .jsonPath("$[0].nodeId").isEqualTo("!a1b2c3d4")
                    .jsonPath("$[0].localpart").isEqualTo("alice")
                    // displayName falls back to the localpart (AccountView carries no
                    // display-name field) — the documented contract.
                    .jsonPath("$[0].displayName").isEqualTo("alice")
                    .jsonPath("$[0].visibility").isEqualTo("private")
                    .jsonPath("$[1].nodeId").isEqualTo("!b2c3d4e5")
                    .jsonPath("$[1].visibility").isEqualTo("channels")
                    .jsonPath("$[2].localpart").isEqualTo("bob")
                    .jsonPath("$[2].displayName").isEqualTo("bob")
                    // owner_subject never crosses this wire — only the localpart does.
                    .jsonPath("$[0].ownerSubject").doesNotExist()
                    .jsonPath("$[0].owner_subject").doesNotExist();

            // DEDUPE: alice's two rows cost exactly ONE admin-bff account read.
            verify(adminBff, times(1)).getAccount(ALICE);
            verify(adminBff, times(1)).getAccount(BOB);
        }

        @Test
        void unresolvableOwner_rowsOmitted_failSoft_restOfMappingSurvives() {
            // carol's subject is a raw Casdoor UUID with no admin-bff account (404-ish
            // error) — her row is OMITTED; alice's row still ships.
            when(repo.listActiveForBridge()).thenReturn(Flux.just(
                    row(ALICE, "!a1b2c3d4", "private"),
                    row("carol-casdoor-uuid", "!dddd0000", "private")));
            when(adminBff.getAccount(ALICE)).thenReturn(Mono.just(account(ALICE, "alice")));
            when(adminBff.getAccount("carol-casdoor-uuid"))
                    .thenReturn(Mono.error(new IllegalStateException("account not found")));

            client.mutateWith(serviceJwt())
                    .get().uri(PATH)
                    .exchange()
                    .expectStatus().isOk()
                    .expectBody()
                    .jsonPath("$.length()").isEqualTo(1)
                    .jsonPath("$[0].nodeId").isEqualTo("!a1b2c3d4")
                    .jsonPath("$[0].localpart").isEqualTo("alice");
        }

        @Test
        void blankPersistedLocalpart_rowOmitted_neverAFabricatedCandidate() {
            // dave HAS an account but no persisted localpart yet (pre-290 row) — his
            // row is omitted rather than falling back to an un-collision-checked value.
            when(repo.listActiveForBridge()).thenReturn(Flux.just(
                    row("google:dave@example.com", "!eeee0000", "private")));
            when(adminBff.getAccount("google:dave@example.com"))
                    .thenReturn(Mono.just(account("google:dave@example.com", "")));

            client.mutateWith(serviceJwt())
                    .get().uri(PATH)
                    .exchange()
                    .expectStatus().isOk()
                    .expectBody()
                    .jsonPath("$.length()").isEqualTo(0);
        }
    }

    // ── STATUS CONTRACT ───────────────────────────────────────────────────────
    @Nested
    class StatusContract {

        @Test
        void statusBatch_aggregatesUpdatedAndIgnoredCounts() {
            // two known radios update; one unknown node id is the fail-soft ignored leg.
            when(service.applyStatus(eq("!a1b2c3d4"), any(), any(), any(), any(), any()))
                    .thenReturn(Mono.just(true));
            when(service.applyStatus(eq("!b2c3d4e5"), any(), any(), any(), any(), any()))
                    .thenReturn(Mono.just(true));
            when(service.applyStatus(eq("!eeeeeeee"), any(), any(), any(), any(), any()))
                    .thenReturn(Mono.just(false));

            client.mutateWith(serviceJwt())
                    .post().uri(STATUS_PATH)
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(List.of(
                            Map.of("nodeId", "!a1b2c3d4", "lastSeenAt", "2026-07-15T12:00:00Z",
                                    "batteryPct", 87, "snr", 7.5, "hopsAway", 2,
                                    "viaDevice", "!aabbccdd"),
                            Map.of("nodeId", "!b2c3d4e5", "batteryPct", 101),
                            Map.of("nodeId", "!eeeeeeee")))
                    .exchange()
                    .expectStatus().isOk()
                    .expectBody()
                    .jsonPath("$.updated").isEqualTo(2)
                    .jsonPath("$.ignored").isEqualTo(1);

            // the full telemetry of the first report reached the service intact.
            verify(service).applyStatus(eq("!a1b2c3d4"),
                    eq(Instant.parse("2026-07-15T12:00:00Z")), eq(87), eq(7.5), eq(2),
                    eq("!aabbccdd"));
        }

        @Test
        void statusBatch_emptyArray_isZeroZero() {
            client.mutateWith(serviceJwt())
                    .post().uri(STATUS_PATH)
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(List.of())
                    .exchange()
                    .expectStatus().isOk()
                    .expectBody()
                    .jsonPath("$.updated").isEqualTo(0)
                    .jsonPath("$.ignored").isEqualTo(0);

            verify(service, never()).applyStatus(any(), any(), any(), any(), any(), any());
        }
    }
}
