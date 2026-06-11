package systems.snapdragon.userbff.profile;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.data.r2dbc.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.r2dbc.core.DatabaseClient;
import reactor.test.StepVerifier;
import systems.snapdragon.userbff.support.TestDatabaseConfig;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * DB-LEVEL enum/domain CHECK slice test over H2 (PostgreSQL-compat) with the REAL
 * Liquibase changelog applied (TestDatabaseConfig → changeset 005's CHECK
 * constraints {@code ck_user_profile_visibility} + {@code ck_user_block_platform}, and
 * changeset 009's {@code ck_connected_client_platform} + {@code ck_connected_client_kind}).
 * Proves the DB rejects the SAME out-of-vocabulary values the API rejects with a
 * 400 — the parity backstop. Raw {@link DatabaseClient} INSERTs so the assertion is
 * the constraint itself, not any application-layer filter.
 */
@DataR2dbcTest
@Import({TestDatabaseConfig.class})
class EnumCheckConstraintTest {

    @Autowired DatabaseClient db;

    // ---- user_profile.visibility ----

    @ParameterizedTest
    @ValueSource(strings = {"secret", "PUBLIC", "internalish", "", "world"})
    void badVisibility_isRejectedByCheckConstraint(String visibility) {
        StepVerifier.create(
                        db.sql("INSERT INTO user_profile (user_id, visibility, "
                                        + "vanity_subdomain_enabled, updated_at) "
                                        + "VALUES (:u, :vis, false, now())")
                                .bind("u", "sub-" + visibility.hashCode())
                                .bind("vis", visibility)
                                .fetch().rowsUpdated())
                .expectError()
                .verify();
    }

    @Test
    void validVisibility_isAccepted() {
        db.sql("INSERT INTO user_profile (user_id, visibility, vanity_subdomain_enabled, updated_at) "
                        + "VALUES ('sub-pub', 'public', false, now())")
                .fetch().rowsUpdated().block();
        db.sql("INSERT INTO user_profile (user_id, visibility, vanity_subdomain_enabled, updated_at) "
                        + "VALUES ('sub-int', 'internal', false, now())")
                .fetch().rowsUpdated().block();
        assertThat(count("user_profile", "user_id IN ('sub-pub','sub-int')")).isEqualTo(2L);
    }

    // ---- user_block.platform ----

    @ParameterizedTest
    @ValueSource(strings = {"irc", "MATRIX", "discord", "", "xmpp"})
    void badPlatform_isRejectedByCheckConstraint(String platform) {
        StepVerifier.create(
                        db.sql("INSERT INTO user_block (id, user_id, target, platform, ts) "
                                        + "VALUES (:id, 'u1', '@t:host', :p, now())")
                                .bind("id", "blk-" + platform.hashCode())
                                .bind("p", platform)
                                .fetch().rowsUpdated())
                .expectError()
                .verify();
    }

    @Test
    void validPlatform_isAccepted() {
        for (String p : new String[] {"matrix", "mastodon", "internal"}) {
            db.sql("INSERT INTO user_block (id, user_id, target, platform, ts) "
                            + "VALUES (:id, 'u1', '@t:host', :p, now())")
                    .bind("id", "blk-" + p).bind("p", p)
                    .fetch().rowsUpdated().block();
        }
        assertThat(count("user_block", "user_id = 'u1'")).isEqualTo(3L);
    }

    // ---- connected_client_audit.platform (009) ----

    @ParameterizedTest
    @ValueSource(strings = {"internal", "MATRIX", "telegram", "", "irc"})
    void badConnectedClientPlatform_isRejectedByCheckConstraint(String platform) {
        StepVerifier.create(
                        db.sql("INSERT INTO connected_client_audit "
                                        + "(id, owner, platform, client_kind, external_ref, created_at) "
                                        + "VALUES (:id, 'u1', :p, 'device', 'ref', now())")
                                .bind("id", "cc-p-" + platform.hashCode())
                                .bind("p", platform)
                                .fetch().rowsUpdated())
                .expectError()
                .verify();
    }

    @Test
    void validConnectedClientPlatform_isAccepted() {
        for (String p : new String[] {"matrix", "mastodon"}) {
            db.sql("INSERT INTO connected_client_audit "
                            + "(id, owner, platform, client_kind, external_ref, created_at) "
                            + "VALUES (:id, 'cc-u', :p, 'device', 'ref', now())")
                    .bind("id", "cc-ok-" + p).bind("p", p)
                    .fetch().rowsUpdated().block();
        }
        assertThat(count("connected_client_audit", "owner = 'cc-u'")).isEqualTo(2L);
    }

    // ---- connected_client_audit.client_kind (009) ----

    @ParameterizedTest
    @ValueSource(strings = {"app", "OAUTH-APP", "session", "", "token"})
    void badConnectedClientKind_isRejectedByCheckConstraint(String kind) {
        StepVerifier.create(
                        db.sql("INSERT INTO connected_client_audit "
                                        + "(id, owner, platform, client_kind, external_ref, created_at) "
                                        + "VALUES (:id, 'u1', 'matrix', :k, 'ref', now())")
                                .bind("id", "cc-k-" + kind.hashCode())
                                .bind("k", kind)
                                .fetch().rowsUpdated())
                .expectError()
                .verify();
    }

    @Test
    void validConnectedClientKind_isAccepted() {
        for (String k : new String[] {"oauth-app", "device"}) {
            db.sql("INSERT INTO connected_client_audit "
                            + "(id, owner, platform, client_kind, external_ref, created_at) "
                            + "VALUES (:id, 'cc-k-u', 'mastodon', :k, 'ref', now())")
                    .bind("id", "cc-kok-" + k).bind("k", k)
                    .fetch().rowsUpdated().block();
        }
        assertThat(count("connected_client_audit", "owner = 'cc-k-u'")).isEqualTo(2L);
    }

    private Long count(String table, String where) {
        return db.sql("SELECT count(*) AS c FROM " + table + " WHERE " + where)
                .map(r -> r.get("c", Long.class)).first().block();
    }
}
