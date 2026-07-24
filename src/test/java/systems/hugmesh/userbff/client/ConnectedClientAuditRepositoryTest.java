package systems.hugmesh.userbff.client;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;
import systems.hugmesh.commons.testsupport.PostgresTestSupport;
import systems.hugmesh.userbff.support.PostgresSliceTestConfig;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * R2DBC slice test for {@link ConnectedClientAuditRepository} against H2
 * (PostgreSQL-compat) with the REAL Liquibase changelog applied (009
 * {@code connected_client_audit}). Verifies the record/list/find/revoke round-trip
 * AND owner-isolation at the SQL layer: one user's connected client is never visible
 * to / revocable by another user's id.
 */
@DataR2dbcTest
@ActiveProfiles("test")
@Import({PostgresSliceTestConfig.class, ConnectedClientAuditRepository.class})
class ConnectedClientAuditRepositoryTest extends PostgresTestSupport {

    @Autowired ConnectedClientAuditRepository repo;

    @Test
    void record_listAndFind_roundTrip() {
        ConnectedClient saved = repo.record("alice", "matrix", ConnectedClient.KIND_DEVICE,
                "DEVABC", "Element on phone").block();
        assertThat(saved.id()).isNotBlank();
        assertThat(saved.owner()).isEqualTo("alice");
        assertThat(saved.platform()).isEqualTo("matrix");
        assertThat(saved.clientKind()).isEqualTo("device");
        assertThat(saved.externalRef()).isEqualTo("DEVABC");
        assertThat(saved.active()).isTrue();

        assertThat(repo.listForOwner("alice").collectList().block())
                .anySatisfy(c -> assertThat(c.externalRef()).isEqualTo("DEVABC"));
        assertThat(repo.find("alice", saved.id()).block().label()).isEqualTo("Element on phone");
    }

    @Test
    void ownerIsolation_oneUserCannotSeeOrRevokeAnother() {
        ConnectedClient aliceClient = repo.record("alice", "mastodon", ConnectedClient.KIND_OAUTH_APP,
                "APP1", "Tusky").block();
        repo.record("bob", "matrix", ConnectedClient.KIND_DEVICE, "DEV2", "Ivory").block();

        // bob's list never shows alice's client
        assertThat(repo.listForOwner("bob").collectList().block())
                .noneSatisfy(c -> assertThat(c.externalRef()).isEqualTo("APP1"));
        // bob cannot find alice's client by id
        assertThat(repo.find("bob", aliceClient.id()).blockOptional()).isEmpty();
        // bob's revoke (owner+id scoped) does NOT touch alice's row
        assertThat(repo.revoke("bob", aliceClient.id()).block()).isEqualTo(0L);
        assertThat(repo.find("alice", aliceClient.id()).block().active()).isTrue();
    }

    @Test
    void revoke_isOwnerAndIdScoped_andIdempotent() {
        ConnectedClient c = repo.record("carol", "matrix", ConnectedClient.KIND_DEVICE, "DEV3", "Element")
                .block();
        assertThat(repo.revoke("carol", c.id()).block()).isEqualTo(1L);
        assertThat(repo.find("carol", c.id()).block().active()).isFalse();
        // second revoke is a no-op (already revoked → 0 rows)
        assertThat(repo.revoke("carol", c.id()).block()).isEqualTo(0L);
    }
}
