package systems.snapdragon.userbff.preference;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.data.r2dbc.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import systems.snapdragon.userbff.support.TestDatabaseConfig;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * R2DBC slice test for {@link UserPreferenceRepository} against H2 (PostgreSQL-
 * compat) with the REAL Liquibase changelog. Verifies the key/value upsert + the
 * owner-keyed composite PK so one user's preferences never collide with another's.
 */
@DataR2dbcTest
@Import({TestDatabaseConfig.class, UserPreferenceRepository.class})
class UserPreferenceRepositoryTest {

    @Autowired UserPreferenceRepository repo;

    @Test
    void set_get_update_roundTrip() {
        assertThat(repo.find("alice", "k").blockOptional()).isEmpty();
        repo.set("alice", "k", "v1").block();
        assertThat(repo.find("alice", "k").block()).isEqualTo("v1");
        repo.set("alice", "k", "v2").block();   // update path
        assertThat(repo.find("alice", "k").block()).isEqualTo("v2");

        Map<String, String> all = repo.findAll("alice").block();
        assertThat(all).containsEntry("k", "v2");
    }

    @Test
    void compositePk_isOwnerScoped() {
        repo.set("alice", "home-guide-dismissed:home", "true").block();
        repo.set("bob", "home-guide-dismissed:home", "true").block();
        // same key under two owners are independent rows
        repo.delete("alice", "home-guide-dismissed:home").block();
        assertThat(repo.find("alice", "home-guide-dismissed:home").blockOptional()).isEmpty();
        assertThat(repo.find("bob", "home-guide-dismissed:home").block()).isEqualTo("true");
    }

    @Test
    void findKeysWithValue_returnsOnlyOwnerKeys() {
        repo.set("alice", "home-guide-dismissed:a", "true").block();
        repo.set("alice", "home-guide-dismissed:b", "true").block();
        repo.set("bob", "home-guide-dismissed:c", "true").block();
        assertThat(repo.findKeysWithValue("alice", "true").collectList().block())
                .containsExactlyInAnyOrder("home-guide-dismissed:a", "home-guide-dismissed:b");
    }
}
