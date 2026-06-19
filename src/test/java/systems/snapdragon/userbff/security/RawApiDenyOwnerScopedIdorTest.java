package systems.snapdragon.userbff.security;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;
import systems.snapdragon.userbff.block.UserBlock;
import systems.snapdragon.userbff.block.UserBlockRepository;
import systems.snapdragon.userbff.notification.UserNotification;
import systems.snapdragon.userbff.notification.UserNotificationRepository;
import systems.snapdragon.userbff.profile.UserProfile;
import systems.snapdragon.userbff.profile.UserProfileRepository;
import systems.snapdragon.userbff.support.TestDatabaseConfig;
import systems.snapdragon.userbff.testsupport.TestIssuer;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * RAW-API-DENY negative security matrix for the user BFF — OWNER-SCOPED IDOR / BOLA,
 * cross-tenant isolation, privilege containment, and authentication fail-closed,
 * driven through the FULL production stack (real {@code SecurityConfig} resource
 * server + the real controllers/services + a real H2 schema) over HTTP.
 *
 * <p><b>Pattern (the federation-api gold exemplar).</b> Two in-process
 * {@link TestIssuer} JWKS servers ({@code brandx}, {@code brandy}) mint real RS256
 * tokens with arbitrary {@code sub}/roles/issuer — wired into
 * {@code app.tenancy.issuers} via {@link DynamicPropertySource} so multi-issuer mode
 * is genuinely active (each brand validates its own tokens; an unlisted issuer 401s).
 * The DB is the real Liquibase-applied schema over H2 ({@link TestDatabaseConfig}). A
 * third issuer ({@code rogue}) is deliberately NOT listed.
 *
 * <p><b>MUTATION-RESISTANT verification.</b> Every negative MUTATION test seeds the
 * VICTIM's row directly through the repository, drives the attacker's denied request
 * over HTTP, and then RE-READS the victim's row through the repository (using the
 * SUPERADMIN-style {@code null} cross-domain bypass so the re-read can SEE any row that
 * was wrongly written) to prove the write did NOT take effect. A 4xx alone is not
 * trusted — the database is the witness.
 *
 * <p><b>These tests assert DENY.</b> If the API ever fails open (a missing owner/domain
 * predicate, a privilege leak, an unknown-issuer accept) one of these turns RED. That
 * red is the FINDING — it must NOT be weakened.
 *
 * <p>Negative classes covered: IDOR/BOLA (body-spoofed owner id + path-named foreign
 * row id), cross-tenant leak (brand-Y token cannot read/write brand-X data),
 * privilege containment (a ROLE_USER token cannot reach the ROLE_SERVICE internal
 * surface nor the ROLE_ADMIN OpenAPI spec), anonymous 401, and forged/unknown-issuer +
 * tampered-signature 401.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("prod-deny-slice")
@Import(TestDatabaseConfig.class)
@DisplayName("Raw-API-deny: owner-scoped IDOR / cross-tenant / privilege / fail-closed")
class RawApiDenyOwnerScopedIdorTest {

    // ── in-process issuers (started before the context so the dynamic props resolve) ──
    private static final TestIssuer BRANDX = new TestIssuer();
    private static final TestIssuer BRANDY = new TestIssuer();
    private static final TestIssuer ROGUE = new TestIssuer();   // NOT trusted

    private static final String DOMAIN_X = "brandx";
    private static final String DOMAIN_Y = "brandy";

    /**
     * Activate genuine multi-issuer mode against the two in-process issuers. The prod
     * (non dev/test) profile name keeps the MOST RESTRICTIVE filter chain (OpenAPI spec
     * gated to ROLE_ADMIN) so the privilege-containment assertions exercise prod.
     */
    @DynamicPropertySource
    static void issuers(DynamicPropertyRegistry r) {
        // brand-X is also the lone back-compat issuer-uri (single-issuer fallback target),
        // but app.tenancy.issuers having two pairs makes the registry genuinely multi-issuer.
        r.add("spring.security.oauth2.resourceserver.jwt.issuer-uri", BRANDX::issuerUri);
        r.add("app.tenancy.issuers", () ->
                BRANDX.issuerUri() + "=" + DOMAIN_X + "," + BRANDY.issuerUri() + "=" + DOMAIN_Y);
    }

    @AfterAll
    static void closeIssuers() {
        BRANDX.close();
        BRANDY.close();
        ROGUE.close();
    }

    @Autowired WebTestClient http;
    @Autowired UserProfileRepository profiles;
    @Autowired UserBlockRepository blocks;
    @Autowired UserNotificationRepository notifications;

    // unique subjects per role so no two tests collide on the shared H2 store.
    private static String victim(String tag)  { return "victim-" + tag; }
    private static String attacker(String tag) { return "attacker-" + tag; }

    private String bearerX(String sub) { return BRANDX.mint(sub, List.of("user")); }
    private String bearerY(String sub) { return BRANDY.mint(sub, List.of("user")); }

    /** Seed one notification for {@code sub} in {@code domain} via the public
     *  insert-if-absent production write path, returning the (caller-supplied) id. The
     *  package-private {@code insertForTest} seam is not reachable from this package. */
    private String seedNotification(String sub, String domain) {
        String id = java.util.UUID.randomUUID().toString();
        // role-change is a valid ck_user_notifications_category value (account-restriction
        // is forced-on; role-change/infra-impacting/feature-availability are the others).
        Boolean inserted = notifications.insertIfAbsent(id, domain, sub, "role-change", "Victim notice", "body").block();
        assertThat(inserted).isTrue();
        return id;
    }

    // ════════════════════════════════════════════════════════════════════════
    // IDOR / BOLA — body-spoofed owner id is IGNORED (owner = jwt.getSubject())
    // ════════════════════════════════════════════════════════════════════════

    @Nested
    @DisplayName("IDOR — body/path naming another user's id is ignored or 404")
    class Idor {

        @Test
        @DisplayName("PUT /profile: attacker's body userId=victim is IGNORED — write lands on attacker, victim untouched")
        void putProfile_bodyUserIdIsIgnored_writeLandsOnAttacker_victimUntouched() {
            String v = victim("prof");
            String a = attacker("prof");
            // Seed the victim's profile in brand-X.
            profiles.save(new UserProfile(v, "vg", "vp", "vtz", "Victim", "internal", false), DOMAIN_X).block();

            // Attacker (brand-X) PUTs a profile whose BODY userId names the victim, trying
            // to overwrite the victim's row (a classic body-spoof IDOR).
            http.put().uri("/bff/user/profile")
                    .header("Authorization", "Bearer " + bearerX(a))
                    .header("Content-Type", "application/json")
                    .bodyValue(Map.of(
                            "userId", v,                 // SPOOFED — must be ignored
                            "gender", "ATTACKER-OVERWRITE",
                            "pronouns", "x",
                            "timezone", "x",
                            "displayName", "Pwned",
                            "visibility", "internal",
                            "vanitySubdomainEnabled", false))
                    .exchange()
                    // The request itself succeeds, but owner is forced to the attacker.
                    .expectStatus().isOk()
                    .expectBody()
                    .jsonPath("$.userId").isEqualTo(a);

            // RE-READ: the VICTIM's row is byte-for-byte unchanged.
            UserProfile victimAfter = profiles.find(v, null).block();
            assertThat(victimAfter).as("victim profile must exist and be untouched").isNotNull();
            assertThat(victimAfter.userId()).isEqualTo(v);
            assertThat(victimAfter.gender())
                    .as("victim's profile must NOT carry the attacker's overwrite")
                    .isEqualTo("vg");
            assertThat(victimAfter.displayName()).isEqualTo("Victim");

            // And the write that DID happen is the attacker's own (separate) row.
            UserProfile attackerAfter = profiles.find(a, null).block();
            assertThat(attackerAfter).isNotNull();
            assertThat(attackerAfter.userId()).isEqualTo(a);
            assertThat(attackerAfter.gender()).isEqualTo("ATTACKER-OVERWRITE");
        }

        @Test
        @DisplayName("DELETE /blocks/{id}: attacker deleting victim's block id does not remove it (re-read)")
        void deleteBlock_foreignId_doesNotDeleteVictimRow() {
            String v = victim("blk");
            String a = attacker("blk");
            UserBlock victimBlock = blocks.add(v, "spammer@evil.example", "internal", DOMAIN_X).block();
            assertThat(victimBlock).isNotNull();
            String foreignId = victimBlock.id();

            // Attacker (brand-X, same domain as victim) tries to delete the victim's block
            // by its id. The service scopes DELETE by (owner, id, domain) so it matches 0
            // rows for the attacker and the service raises notFound → 404. Either a 404 (the
            // current behaviour) or a 204 no-op is an acceptable DENY here; the load-bearing
            // assertion is the re-read below: the victim's row must SURVIVE.
            http.delete().uri("/bff/user/blocks/{id}", foreignId)
                    .header("Authorization", "Bearer " + bearerX(a))
                    .exchange()
                    .expectStatus().isNotFound();

            // RE-READ: the victim's block is STILL there (cross-domain bypass read).
            List<UserBlock> victimBlocks = blocks.listForOwner(v, null).collectList().block();
            assertThat(victimBlocks).as("victim's block must survive the attacker's delete")
                    .extracting(UserBlock::id).contains(foreignId);
        }

        @Test
        @DisplayName("POST /notifications/{id}/read: attacker marking victim's notification is 404, stays unread (re-read)")
        void markRead_foreignId_is404_andStaysUnread() {
            String v = victim("notif");
            String a = attacker("notif");
            String notifId = seedNotification(v, DOMAIN_X);
            assertThat(notifId).isNotNull();

            // Attacker (brand-X) marks the victim's notification read. It is not the
            // attacker's own (owner+domain) row → 404, no cross-user mark.
            http.post().uri("/bff/user/notifications/{id}/read", notifId)
                    .header("Authorization", "Bearer " + bearerX(a))
                    .exchange()
                    .expectStatus().isNotFound();

            // RE-READ: the victim's notification is STILL unread (readAt null).
            List<UserNotification> victimNotifs =
                    notifications.listForOwner(v, null, 50).collectList().block();
            assertThat(victimNotifs).hasSize(1);
            assertThat(victimNotifs.get(0).id()).isEqualTo(notifId);
            assertThat(victimNotifs.get(0).readAt())
                    .as("victim's notification must remain unread after the denied cross-user mark")
                    .isNull();
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // CROSS-TENANT — a brand-Y token can never read/write brand-X data
    // ════════════════════════════════════════════════════════════════════════

    @Nested
    @DisplayName("Cross-tenant — brand-Y token is scoped to brand-Y, never brand-X")
    class CrossTenant {

        @Test
        @DisplayName("GET /profile: a brand-Y token cannot read a brand-X user's profile row")
        void getProfile_brandYToken_cannotReadBrandXRow() {
            // A brand-X user exists with a distinctive profile. A brand-Y token (a DIFFERENT
            // subject — Casdoor subjects are per-brand unique) must resolve ONLY its own
            // (brand-Y) scope: it gets the empty default, never the brand-X user's row.
            String brandXUser = "brandx-user-read";
            String brandYUser = "brandy-user-read";
            profiles.save(new UserProfile(brandXUser, "X-ONLY", "p", "tz", "BrandX User", "internal", false), DOMAIN_X).block();

            http.get().uri("/bff/user/profile")
                    .header("Authorization", "Bearer " + bearerY(brandYUser))   // brand-Y issuer
                    .exchange()
                    .expectStatus().isOk()
                    .expectBody()
                    // empty default for the brand-Y caller — the owner is the brand-Y subject,
                    // and there is NO leakage of the brand-X user's gender.
                    .jsonPath("$.userId").isEqualTo(brandYUser)
                    .jsonPath("$.gender").value(g -> assertThat(g).isNotEqualTo("X-ONLY"));

            // RE-READ: the brand-X user's row is untouched and was never exposed.
            UserProfile brandXRow = profiles.find(brandXUser, DOMAIN_X).block();
            assertThat(brandXRow).isNotNull();
            assertThat(brandXRow.gender()).isEqualTo("X-ONLY");
        }

        @Test
        @DisplayName("PUT /profile: a brand-Y write lands in brand-Y, never touches a brand-X user's row")
        void putProfile_brandYWrite_doesNotTouchBrandXRow() {
            String brandXUser = "brandx-user-write";
            String brandYUser = "brandy-user-write";
            profiles.save(new UserProfile(brandXUser, "X-ORIGINAL", "p", "tz", "BrandX User", "internal", false), DOMAIN_X).block();

            http.put().uri("/bff/user/profile")
                    .header("Authorization", "Bearer " + bearerY(brandYUser))
                    .header("Content-Type", "application/json")
                    .bodyValue(Map.of(
                            "userId", brandXUser,        // SPOOFED — naming the brand-X user
                            "gender", "Y-WRITE",
                            "pronouns", "p", "timezone", "tz",
                            "displayName", "BrandY User",
                            "visibility", "internal",
                            "vanitySubdomainEnabled", false))
                    .exchange()
                    .expectStatus().isOk()
                    .expectBody()
                    // owner forced to the brand-Y caller — the spoofed brand-X id is ignored.
                    .jsonPath("$.userId").isEqualTo(brandYUser);

            // RE-READ: the brand-X user's row is byte-for-byte unchanged; the write landed
            // under the brand-Y caller in the brand-Y scope.
            UserProfile brandXRow = profiles.find(brandXUser, DOMAIN_X).block();
            assertThat(brandXRow.gender()).as("brand-X user's row must not be overwritten by a brand-Y write")
                    .isEqualTo("X-ORIGINAL");
            UserProfile brandYRow = profiles.find(brandYUser, DOMAIN_Y).block();
            assertThat(brandYRow).isNotNull();
            assertThat(brandYRow.gender()).isEqualTo("Y-WRITE");
        }

        @Test
        @DisplayName("GET /notifications: brand-Y token does not see the subject's brand-X notifications")
        void listNotifications_brandYToken_doesNotSeeBrandXRows() {
            String sub = "shared-subject-notif-xtenant";
            seedNotification(sub, DOMAIN_X);

            http.get().uri("/bff/user/notifications")
                    .header("Authorization", "Bearer " + bearerY(sub))
                    .exchange()
                    .expectStatus().isOk()
                    .expectBody()
                    .jsonPath("$.length()").isEqualTo(0);   // nothing in the brand-Y scope
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // PRIVILEGE CONTAINMENT — a ROLE_USER token cannot reach elevated surfaces
    // ════════════════════════════════════════════════════════════════════════

    @Nested
    @DisplayName("Privilege containment — ROLE_USER cannot reach elevated surfaces")
    class PrivilegeContainment {

        @Test
        @DisplayName("POST /bff/user/internal/notifications: ROLE_USER is FORBIDDEN (ROLE_SERVICE only)")
        void internalDeliver_roleUser_is403() {
            // The internal deliver endpoint takes its target (domain, userSubject) from the
            // BODY — a human reaching it could spoof a notification to ANY user. It is gated
            // to ROLE_SERVICE EXCLUSIVELY. A ROLE_USER token must be forbidden, and crucially
            // must NOT write a row for the body-named target.
            String target = "spoof-target-user";
            http.post().uri("/bff/user/internal/notifications")
                    .header("Authorization", "Bearer " + bearerX(attacker("internal")))
                    .header("Content-Type", "application/json")
                    .bodyValue(Map.of(
                            "domain", DOMAIN_X,
                            "userSubject", target,
                            "category", "general",
                            "title", "Spoofed",
                            "sourceTable", "evil",
                            "sourceId", "1"))
                    .exchange()
                    .expectStatus().isForbidden();

            // RE-READ: no notification was delivered to the spoofed target.
            List<UserNotification> rows = notifications.listForOwner(target, null, 50).collectList().block();
            assertThat(rows).as("a ROLE_USER must not be able to spoof a notification to another user")
                    .isEmpty();
        }

        @Test
        @DisplayName("GET /bff/user/internal/notifications surface: SUPERADMIN is ALSO denied (no edge to SERVICE)")
        void internalDeliver_superadmin_is403() {
            // The role hierarchy has SUPERADMIN > ADMIN/MOD/USER but NO edge to SERVICE, so
            // even a SUPERADMIN human token must be denied the service-only internal surface.
            String token = BRANDX.mint(attacker("internal-sa"), List.of("superadmin"));
            http.post().uri("/bff/user/internal/notifications")
                    .header("Authorization", "Bearer " + token)
                    .header("Content-Type", "application/json")
                    .bodyValue(Map.of(
                            "domain", DOMAIN_X, "userSubject", "x", "category", "general",
                            "title", "t", "sourceTable", "s", "sourceId", "1"))
                    .exchange()
                    .expectStatus().isForbidden();
        }

        @Test
        @DisplayName("GET /v3/api-docs (prod profile): ROLE_USER is FORBIDDEN (spec is ROLE_ADMIN)")
        void openApiSpec_roleUser_is403_inProdProfile() {
            // The prod (!dev & !test) chain gates the OpenAPI spec to ROLE_ADMIN/SUPERADMIN.
            // A plain ROLE_USER token must not be able to exfiltrate the API contract.
            http.get().uri("/v3/api-docs")
                    .header("Authorization", "Bearer " + bearerX(attacker("spec")))
                    .exchange()
                    .expectStatus().isForbidden();
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // FAIL-CLOSED — anonymous + forged/unknown-issuer + tampered signature → 401
    // ════════════════════════════════════════════════════════════════════════

    @Nested
    @DisplayName("Fail-closed — anonymous / forged-token / unknown-issuer / tampered → 401")
    class FailClosed {

        @Test
        @DisplayName("anonymous on every owner-scoped surface is 401")
        void anonymous_is401_everywhere() {
            expect401(http.get().uri("/bff/user/profile"));
            expect401(http.put().uri("/bff/user/profile").header("Content-Type", "application/json")
                    .bodyValue(Map.of("visibility", "internal")));
            expect401(http.get().uri("/bff/user/blocks"));
            expect401(http.get().uri("/bff/user/notifications"));
            expect401(http.get().uri("/bff/user/self-silence/status"));
            expect401(http.get().uri("/bff/user/notification-preferences"));
            expect401(http.get().uri("/bff/user/home-guide"));
            // The service-only internal surface is also 401 anonymous (auth before authz).
            expect401(http.post().uri("/bff/user/internal/notifications").header("Content-Type", "application/json")
                    .bodyValue(Map.of("domain", DOMAIN_X, "userSubject", "x", "category", "general",
                            "title", "t", "sourceTable", "s", "sourceId", "1")));
        }

        @Test
        @DisplayName("a token from an UNKNOWN (untrusted) issuer is 401 — fail-closed, never default-accept")
        void unknownIssuerToken_is401() {
            // The rogue issuer is a well-formed, correctly-signed JWT — it is simply NOT in
            // app.tenancy.issuers. The per-issuer resolver returns no manager → 401. A forged
            // superadmin role on it changes nothing: the issuer never validates.
            String forged = ROGUE.mint("attacker", List.of("superadmin", "admin", "service"));
            http.get().uri("/bff/user/profile")
                    .header("Authorization", "Bearer " + forged)
                    .exchange()
                    .expectStatus().isUnauthorized();
        }

        @Test
        @DisplayName("a tampered-signature token is 401")
        void tamperedSignature_is401() {
            String token = bearerX("user-x");
            String tampered = token.substring(0, token.length() - 4) + "AAAA";
            http.get().uri("/bff/user/profile")
                    .header("Authorization", "Bearer " + tampered)
                    .exchange()
                    .expectStatus().isUnauthorized();
        }

        @Test
        @DisplayName("a garbage (non-JWT) bearer is 401")
        void garbageBearer_is401() {
            http.get().uri("/bff/user/profile")
                    .header("Authorization", "Bearer not-a-jwt")
                    .exchange()
                    .expectStatus().isUnauthorized();
        }

        private void expect401(WebTestClient.RequestHeadersSpec<?> spec) {
            spec.exchange().expectStatus().isUnauthorized();
        }
    }
}
