package systems.hugmesh.userbff.block;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;
import systems.hugmesh.commons.testsupport.PostgresTestSupport;
import systems.hugmesh.userbff.support.PostgresSliceTestConfig;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * R2DBC slice test for {@link UserBlockRepository} against H2 (PostgreSQL-compat)
 * with the REAL Liquibase changelog. Verifies the add/list/delete round-trip AND
 * owner-enforcement at the SQL layer: a user only ever lists their own blocks, and
 * a delete scoped by (owner, id) cannot remove another user's block even with a
 * known id.
 */
@DataR2dbcTest
@ActiveProfiles("test")
@Import({PostgresSliceTestConfig.class, UserBlockRepository.class})
class UserBlockRepositoryTest extends PostgresTestSupport {

    @Autowired UserBlockRepository repo;

    @Test
    void addListDelete_roundTrip() {
        assertThat(repo.listForOwner("alice").collectList().block()).isEmpty();

        UserBlock saved = repo.add("alice", "@spammer:evil.example", "matrix").block();
        assertThat(saved.id()).isNotBlank();
        assertThat(saved.userId()).isEqualTo("alice");
        assertThat(saved.ts()).isNotNull();

        List<UserBlock> mine = repo.listForOwner("alice").collectList().block();
        assertThat(mine).hasSize(1);
        assertThat(mine.get(0).target()).isEqualTo("@spammer:evil.example");
        assertThat(mine.get(0).platform()).isEqualTo("matrix");

        assertThat(repo.delete("alice", saved.id()).block()).isEqualTo(1L);
        assertThat(repo.listForOwner("alice").collectList().block()).isEmpty();
    }

    @Test
    void listAndDelete_areOwnerScoped() {
        UserBlock aliceBlock = repo.add("alice", "@x:evil", "matrix").block();
        repo.add("bob", "@y:evil", "mastodon").block();

        // alice only sees her own
        assertThat(repo.listForOwner("alice").collectList().block()).hasSize(1);
        // bob cannot delete alice's block even with the exact id
        assertThat(repo.delete("bob", aliceBlock.id()).block()).isEqualTo(0L);
        assertThat(repo.listForOwner("alice").collectList().block()).hasSize(1);
        // alice can
        assertThat(repo.delete("alice", aliceBlock.id()).block()).isEqualTo(1L);
    }
}
