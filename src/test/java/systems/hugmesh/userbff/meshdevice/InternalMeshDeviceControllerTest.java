package systems.hugmesh.userbff.meshdevice;

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
import systems.hugmesh.commons.web.ApiException;
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
 *   <li><b>MODERATION SERVICE-ONLY GATE</b> — the same role matrix re-asserted against
 *       EACH of the three moderation endpoints (they are strictly more dangerous than
 *       the bridge legs: cross-owner identity AND state mutation), including the case
 *       that matters most here — a real {@code ROLE_MOD} token, the very principal this
 *       data is FOR, is DENIED on this hop (a moderator arrives via mod-bff, which
 *       presents the service principal).</li>
 *   <li><b>MODERATION CONTRACT</b> — the console row carries the two fields the
 *       user-facing shape withholds ({@code ownerSubject}, {@code revokedBy}); filters
 *       reach the service verbatim and absent/blank both mean UNSCOPED (a blank domain
 *       would be a brand nobody is in); an unresolvable owner KEEPS its row with a null
 *       localpart (unlike the bridge, which omits it); and revoke/restore surface the
 *       service's 409/404 plus the 400s for a missing reason/moderator.</li>
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
    private static final String MODERATION_PATH = "/bff/user/internal/mesh-devices/moderation";
    private static final String REVOKE_PATH = "/bff/user/internal/mesh-devices/dev-1/revoke";
    private static final String RESTORE_PATH = "/bff/user/internal/mesh-devices/dev-1/restore";

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

    /** A REVOKED row with the audit trio stamped — what the moderation surface returns
     *  after a revoke (and what the console list shows for a pulled radio). */
    private static MeshDeviceEntity revokedRow(String owner, String nodeId, String domain) {
        return new MeshDeviceEntity("id-" + nodeId, owner, domain, nodeId, null,
                "private", MeshDevice.STATE_REVOKED, "mod:alice", Instant.now(),
                "spoofing traffic", null, null, null, null, null, Instant.now());
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

    // ── MODERATION: SERVICE-ONLY GATE ─────────────────────────────────────────
    /**
     * The moderation leg carries the SAME privilege boundary as the bridge legs and is
     * strictly MORE dangerous (it lists every owner's radios AND mutates their state), so
     * the whole role matrix is re-asserted against each of its three endpoints rather
     * than assumed from the shared class-level {@code @PreAuthorize}. Every denial also
     * proves the collaborators were NEVER reached.
     */
    @Nested
    class ModerationServiceOnlyGate {

        @Test
        void moderationList_normalUser_isForbidden_nothingReached() {
            client.mutateWith(mockJwt().jwt(j -> j.subject("mallory")).authorities(authorities("ROLE_USER")))
                    .get().uri(MODERATION_PATH)
                    .exchange()
                    .expectStatus().isForbidden();

            verify(service, never()).listForModeration(any(), any(), any());
            verify(adminBff, never()).getAccount(anyString());
        }

        @Test
        void moderationList_mod_isForbidden_theModeratorRoleIsNOTTheServiceRole() {
            // A ROLE_MOD principal is precisely who this data is FOR — but not on THIS
            // hop: a moderator reaches it through mod-bff, which presents the service
            // principal. A human MOD token must never read user-bff's internal surface.
            client.mutateWith(mockJwt().jwt(j -> j.subject("a-mod"))
                            .authorities(authorities("ROLE_USER", "ROLE_MOD")))
                    .get().uri(MODERATION_PATH)
                    .exchange()
                    .expectStatus().isForbidden();

            verify(service, never()).listForModeration(any(), any(), any());
        }

        @Test
        void moderationList_admin_and_superadmin_areForbidden() {
            client.mutateWith(mockJwt().jwt(j -> j.subject("an-admin"))
                            .authorities(authorities("ROLE_USER", "ROLE_ADMIN")))
                    .get().uri(MODERATION_PATH)
                    .exchange()
                    .expectStatus().isForbidden();
            client.mutateWith(mockJwt().jwt(j -> j.subject("a-superadmin"))
                            .authorities(authorities("ROLE_USER", "ROLE_SUPERADMIN")))
                    .get().uri(MODERATION_PATH)
                    .exchange()
                    .expectStatus().isForbidden();

            verify(service, never()).listForModeration(any(), any(), any());
        }

        @Test
        void moderationList_anonymous_isUnauthorized() {
            client.get().uri(MODERATION_PATH).exchange().expectStatus().isUnauthorized();
            verify(service, never()).listForModeration(any(), any(), any());
        }

        @Test
        void revoke_nonServicePrincipals_areDenied_serviceNeverReached() {
            for (String role : new String[] {"ROLE_USER", "ROLE_MOD", "ROLE_ADMIN", "ROLE_SUPERADMIN"}) {
                client.mutateWith(mockJwt().jwt(j -> j.subject("mallory"))
                                .authorities(authorities("ROLE_USER", role)))
                        .post().uri(REVOKE_PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .bodyValue(Map.of("reason", "spoofing", "moderator", "mallory"))
                        .exchange()
                        .expectStatus().isForbidden();
            }
            client.post().uri(REVOKE_PATH)
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(Map.of("reason", "spoofing", "moderator", "mallory"))
                    .exchange()
                    .expectStatus().isUnauthorized();

            verify(service, never()).revoke(any(), any(), any(), any());
        }

        @Test
        void restore_nonServicePrincipals_areDenied_serviceNeverReached() {
            for (String role : new String[] {"ROLE_USER", "ROLE_MOD", "ROLE_ADMIN", "ROLE_SUPERADMIN"}) {
                client.mutateWith(mockJwt().jwt(j -> j.subject("mallory"))
                                .authorities(authorities("ROLE_USER", role)))
                        .post().uri(RESTORE_PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .bodyValue(Map.of("moderator", "mallory"))
                        .exchange()
                        .expectStatus().isForbidden();
            }
            client.post().uri(RESTORE_PATH)
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(Map.of("moderator", "mallory"))
                    .exchange()
                    .expectStatus().isUnauthorized();

            verify(service, never()).restore(any(), any(), any());
        }
    }

    // ── MODERATION CONTRACT ───────────────────────────────────────────────────
    @Nested
    class ModerationContract {

        @Test
        void moderationList_carriesOwnerIdentity_andPassesTheFiltersThrough() {
            when(service.listForModeration("revoked", "brandx", 25))
                    .thenReturn(Flux.just(revokedRow(ALICE, "!a1b2c3d4", "brandx")));
            when(adminBff.getAccount(ALICE)).thenReturn(Mono.just(account(ALICE, "alice")));

            client.mutateWith(serviceJwt())
                    .get().uri(MODERATION_PATH + "?state=revoked&domain=brandx&limit=25")
                    .exchange()
                    .expectStatus().isOk()
                    .expectBody()
                    .jsonPath("$.length()").isEqualTo(1)
                    .jsonPath("$[0].nodeId").isEqualTo("!a1b2c3d4")
                    // The two fields the USER-facing wire shape deliberately withholds —
                    // present here because only a service principal can reach this.
                    .jsonPath("$[0].ownerSubject").isEqualTo(ALICE)
                    .jsonPath("$[0].revokedBy").isEqualTo("mod:alice")
                    .jsonPath("$[0].ownerLocalpart").isEqualTo("alice")
                    .jsonPath("$[0].state").isEqualTo("revoked")
                    .jsonPath("$[0].revokeReason").isEqualTo("spoofing traffic")
                    .jsonPath("$[0].domain").isEqualTo("brandx");

            // The filters reached the service verbatim (no silent widening of the scope).
            verify(service).listForModeration("revoked", "brandx", 25);
        }

        @Test
        void moderationList_omittedFilters_arriveAsNull_notAsBlankStrings() {
            when(service.listForModeration(null, null, null)).thenReturn(Flux.empty());

            client.mutateWith(serviceJwt())
                    .get().uri(MODERATION_PATH)
                    .exchange()
                    .expectStatus().isOk();

            // A blank "" domain would be a brand nobody is in — an empty console that
            // silently reads as "no devices". Absent MUST mean unscoped.
            verify(service).listForModeration(null, null, null);
        }

        @Test
        void moderationList_blankFilters_areAlsoUnset() {
            when(service.listForModeration(null, null, null)).thenReturn(Flux.empty());

            client.mutateWith(serviceJwt())
                    .get().uri(MODERATION_PATH + "?state=&domain=")
                    .exchange()
                    .expectStatus().isOk();

            verify(service).listForModeration(null, null, null);
        }

        @Test
        void moderationList_unknownState_is400_beforeTheService() {
            client.mutateWith(serviceJwt())
                    .get().uri(MODERATION_PATH + "?state=banned")
                    .exchange()
                    .expectStatus().isBadRequest();

            verify(service, never()).listForModeration(any(), any(), any());
        }

        @Test
        void moderationList_unresolvableOwner_keepsTheRow_withANullLocalpart() {
            // The BRIDGE omits an un-attributable row; the CONSOLE must not — a
            // moderator who cannot see the un-attributable radio cannot revoke it.
            when(service.listForModeration(null, null, null)).thenReturn(Flux.just(
                    row(ALICE, "!a1b2c3d4", "private"),
                    row("carol-casdoor-uuid", "!dddd0000", "private")));
            when(adminBff.getAccount(ALICE)).thenReturn(Mono.just(account(ALICE, "alice")));
            when(adminBff.getAccount("carol-casdoor-uuid"))
                    .thenReturn(Mono.error(new IllegalStateException("account not found")));

            client.mutateWith(serviceJwt())
                    .get().uri(MODERATION_PATH)
                    .exchange()
                    .expectStatus().isOk()
                    .expectBody()
                    .jsonPath("$.length()").isEqualTo(2)
                    .jsonPath("$[0].ownerLocalpart").isEqualTo("alice")
                    .jsonPath("$[1].nodeId").isEqualTo("!dddd0000")
                    .jsonPath("$[1].ownerLocalpart").doesNotExist()
                    // the subject is still there, so the row is still actionable.
                    .jsonPath("$[1].ownerSubject").isEqualTo("carol-casdoor-uuid");
        }

        @Test
        void moderationList_resolvesEachOwnerOnce() {
            when(service.listForModeration(null, null, null)).thenReturn(Flux.just(
                    row(ALICE, "!a1b2c3d4", "private"),
                    row(ALICE, "!b2c3d4e5", "channels"),
                    row(BOB, "!c3d4e5f6", "friends")));
            when(adminBff.getAccount(ALICE)).thenReturn(Mono.just(account(ALICE, "alice")));
            when(adminBff.getAccount(BOB)).thenReturn(Mono.just(account(BOB, "bob")));

            client.mutateWith(serviceJwt())
                    .get().uri(MODERATION_PATH)
                    .exchange()
                    .expectStatus().isOk()
                    .expectBody().jsonPath("$.length()").isEqualTo(3);

            verify(adminBff, times(1)).getAccount(ALICE);
            verify(adminBff, times(1)).getAccount(BOB);
        }

        @Test
        void revoke_servicePrincipal_returnsTheRevokedRow() {
            when(service.revoke("dev-1", "brandx", "mod:alice", "spoofing traffic"))
                    .thenReturn(Mono.just(revokedRow(ALICE, "!a1b2c3d4", "brandx")));
            when(adminBff.getAccount(ALICE)).thenReturn(Mono.just(account(ALICE, "alice")));

            client.mutateWith(serviceJwt())
                    .post().uri(REVOKE_PATH)
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(Map.of("reason", "spoofing traffic", "moderator", "mod:alice",
                            "domain", "brandx"))
                    .exchange()
                    .expectStatus().isOk()
                    .expectBody()
                    .jsonPath("$.state").isEqualTo("revoked")
                    .jsonPath("$.revokedBy").isEqualTo("mod:alice")
                    .jsonPath("$.ownerLocalpart").isEqualTo("alice");
        }

        @Test
        void revoke_alreadyRevoked_is409_and_unknownId_is404() {
            when(service.revoke(eq("dev-1"), any(), anyString(), anyString()))
                    .thenReturn(Mono.error(ApiException.conflict("mesh device is already revoked")));
            client.mutateWith(serviceJwt())
                    .post().uri(REVOKE_PATH)
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(Map.of("reason", "spoofing", "moderator", "mod:alice"))
                    .exchange()
                    .expectStatus().isEqualTo(HttpStatus.CONFLICT);

            when(service.revoke(eq("dev-404"), any(), anyString(), anyString()))
                    .thenReturn(Mono.error(ApiException.notFound("no such mesh device")));
            client.mutateWith(serviceJwt())
                    .post().uri(PATH + "/dev-404/revoke")
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(Map.of("reason", "spoofing", "moderator", "mod:alice"))
                    .exchange()
                    .expectStatus().isNotFound();
        }

        @Test
        void revoke_withoutAReason_is400_beforeTheService() {
            // The reason is what the OWNER is shown — a revocation without one leaves a
            // user with a dead radio and no explanation.
            client.mutateWith(serviceJwt())
                    .post().uri(REVOKE_PATH)
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(Map.of("moderator", "mod:alice"))
                    .exchange()
                    .expectStatus().isBadRequest();

            client.mutateWith(serviceJwt())
                    .post().uri(REVOKE_PATH)
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(Map.of("reason", "   ", "moderator", "mod:alice"))
                    .exchange()
                    .expectStatus().isBadRequest();

            verify(service, never()).revoke(any(), any(), any(), any());
        }

        @Test
        void revoke_withoutAModerator_is400_theAuditStampIsNotOptional() {
            client.mutateWith(serviceJwt())
                    .post().uri(REVOKE_PATH)
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(Map.of("reason", "spoofing"))
                    .exchange()
                    .expectStatus().isBadRequest();

            verify(service, never()).revoke(any(), any(), any(), any());
        }

        @Test
        void restore_servicePrincipal_returnsTheClearedRow() {
            when(service.restore("dev-1", "brandx", "mod:bob"))
                    .thenReturn(Mono.just(row(ALICE, "!a1b2c3d4", "private")));
            when(adminBff.getAccount(ALICE)).thenReturn(Mono.just(account(ALICE, "alice")));

            client.mutateWith(serviceJwt())
                    .post().uri(RESTORE_PATH)
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(Map.of("moderator", "mod:bob", "domain", "brandx"))
                    .exchange()
                    .expectStatus().isOk()
                    .expectBody()
                    .jsonPath("$.state").isEqualTo("active")
                    // the audit trio is CLEARED by the restore.
                    .jsonPath("$.revokedBy").doesNotExist()
                    .jsonPath("$.revokeReason").doesNotExist()
                    .jsonPath("$.revokedAt").doesNotExist();
        }

        @Test
        void restore_notRevoked_is409_and_unknownId_is404() {
            when(service.restore(eq("dev-1"), any(), anyString()))
                    .thenReturn(Mono.error(ApiException.conflict(
                            "mesh device is not revoked — nothing to restore")));
            client.mutateWith(serviceJwt())
                    .post().uri(RESTORE_PATH)
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(Map.of("moderator", "mod:bob"))
                    .exchange()
                    .expectStatus().isEqualTo(HttpStatus.CONFLICT);

            when(service.restore(eq("dev-404"), any(), anyString()))
                    .thenReturn(Mono.error(ApiException.notFound("no such mesh device")));
            client.mutateWith(serviceJwt())
                    .post().uri(PATH + "/dev-404/restore")
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(Map.of("moderator", "mod:bob"))
                    .exchange()
                    .expectStatus().isNotFound();
        }

        @Test
        void restore_withoutAModerator_is400_beforeTheService() {
            client.mutateWith(serviceJwt())
                    .post().uri(RESTORE_PATH)
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(Map.of())
                    .exchange()
                    .expectStatus().isBadRequest();

            verify(service, never()).restore(any(), any(), any());
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
