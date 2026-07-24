package systems.hugmesh.userbff.profile;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.r2dbc.core.DatabaseClient;
import reactor.test.StepVerifier;
import systems.hugmesh.userbff.support.TestDatabaseConfig;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * DB-LEVEL reserved-username guard slice test over H2 (PostgreSQL-compat) with the
 * REAL Liquibase changelog applied (TestDatabaseConfig → changeset 004's CHECK
 * constraint {@code ck_user_profile_vanity_username_reserved}). Proves the backstop
 * independent of the service: a reserved {@code vanity_username} insert is REJECTED
 * by the DB (case-insensitively), while a normal username and a NULL vanity_username
 * are accepted.
 */
@DataR2dbcTest
@Import({TestDatabaseConfig.class})
class VanityUsernameConstraintTest {

    @Autowired DatabaseClient db;

    private Long countFor(String userId) {
        return db.sql("SELECT count(*) AS c FROM user_profile WHERE user_id = :u")
                .bind("u", userId).map(r -> r.get("c", Long.class)).first().block();
    }

    @ParameterizedTest
    @ValueSource(strings = {"admin", "api", "login", "mod", "bff", "user", "games",
            "play", "id", "www", "ADMIN", "Api", "GAMES"})
    void reservedVanityUsernameInsert_isRejectedByCheckConstraint(String reserved) {
        StepVerifier.create(
                        db.sql("INSERT INTO user_profile (user_id, visibility, "
                                        + "vanity_subdomain_enabled, vanity_username, updated_at) "
                                        + "VALUES (:u, 'public', true, :vu, now())")
                                .bind("u", "sub-" + reserved)
                                .bind("vu", reserved)
                                .fetch().rowsUpdated())
                .expectError() // CHECK violation surfaces as an R2DBC data-integrity error
                .verify();
    }

    /**
     * The 021 canonical-sync additions (reserved-prefixes.yaml revision 9 = 82
     * labels): the Character Forge track labels ({@code character-forge} +
     * the games-side wasm slugs), the revision 7/8 MDM/attestation prefixes
     * ({@code hmdm}/{@code attest}), and a sample of the previously-drifted
     * revision 3-6 labels ({@code character-studio}/{@code wiki}/{@code tube}/
     * {@code superadmin}/{@code v1}/{@code ai}/{@code index.html}) are all
     * rejected by the re-added CHECK — case-insensitively. NOTE: with the
     * auth-core pin at 2.4.1 (canonical revision 9) the revision 7-9 labels are
     * ALSO rejected as a service-layer 400 (see
     * {@code ProfileServiceReservedUsernameTest}); this DB backstop remains the
     * fail-closed defence-in-depth beneath that guard.
     */
    @ParameterizedTest
    @ValueSource(strings = {
            "character-forge", "games-character-forge", "games-shadows-of-the-net",
            "hmdm", "attest", "CHARACTER-FORGE", "Character-Forge",
            "character-studio", "wiki", "tube", "superadmin", "v1", "ai", "index.html"})
    void canonicalSyncReservedVanityUsernameInsert_isRejectedByCheckConstraint(String reserved) {
        StepVerifier.create(
                        db.sql("INSERT INTO user_profile (user_id, visibility, "
                                        + "vanity_subdomain_enabled, vanity_username, updated_at) "
                                        + "VALUES (:u, 'public', true, :vu, now())")
                                .bind("u", "sub-" + reserved)
                                .bind("vu", reserved)
                                .fetch().rowsUpdated())
                .expectError() // CHECK violation surfaces as an R2DBC data-integrity error
                .verify();
    }

    @Test
    void characterForgeAdjacentUsername_isAccepted() {
        // The CHECK is an exact-label match, not a prefix match: an ADJACENT
        // handle ('characterforge') is NOT captured by the reserved list —
        // proving 021 did not widen beyond the canonical labels. (Confusable /
        // skeleton folding is the service layer's job, not this constraint's.)
        db.sql("INSERT INTO user_profile (user_id, visibility, vanity_subdomain_enabled, "
                        + "vanity_username, updated_at) "
                        + "VALUES ('sub-cfadj', 'public', true, 'characterforge', now())")
                .fetch().rowsUpdated().block();
        assertThat(countFor("sub-cfadj")).isEqualTo(1L);
    }

    @Test
    void normalVanityUsername_isAccepted() {
        db.sql("INSERT INTO user_profile (user_id, visibility, vanity_subdomain_enabled, "
                        + "vanity_username, updated_at) VALUES ('sub-carol', 'public', true, 'carol', now())")
                .fetch().rowsUpdated().block();
        assertThat(countFor("sub-carol")).isEqualTo(1L);
    }

    @Test
    void nullVanityUsername_isAccepted() {
        // vanity disabled → NULL vanity_username → the CHECK's IS NULL branch passes.
        db.sql("INSERT INTO user_profile (user_id, visibility, vanity_subdomain_enabled, updated_at) "
                        + "VALUES ('sub-none', 'internal', false, now())")
                .fetch().rowsUpdated().block();
        assertThat(countFor("sub-none")).isEqualTo(1L);
    }
}
