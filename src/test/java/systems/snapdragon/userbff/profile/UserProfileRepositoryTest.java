package systems.snapdragon.userbff.profile;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.data.r2dbc.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import systems.snapdragon.userbff.support.TestDatabaseConfig;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * R2DBC slice test for {@link UserProfileRepository} against H2 (PostgreSQL-compat)
 * with the REAL Liquibase changelog applied by {@link TestDatabaseConfig}. Verifies
 * the upsert round-trip AND owner-isolation at the SQL layer: one user's profile is
 * never visible to / overwritten by another user's id.
 */
@DataR2dbcTest
@Import({TestDatabaseConfig.class, UserProfileRepository.class})
class UserProfileRepositoryTest {

    @Autowired UserProfileRepository repo;

    @Test
    void upsert_roundTrip() {
        assertThat(repo.find("alice").blockOptional()).isEmpty();

        UserProfile saved = repo.save(new UserProfile("alice", "f", "she/her", "UTC", "Alice", "public", true)).block();
        assertThat(saved.userId()).isEqualTo("alice");

        UserProfile got = repo.find("alice").block();
        assertThat(got.pronouns()).isEqualTo("she/her");
        assertThat(got.displayName()).isEqualTo("Alice");
        assertThat(got.visibility()).isEqualTo("public");
        assertThat(got.vanitySubdomainEnabled()).isTrue();

        // update path: same owner, changed fields
        repo.save(new UserProfile("alice", "f", "they/them", "PST", "Al", "internal", false)).block();
        UserProfile updated = repo.find("alice").block();
        assertThat(updated.pronouns()).isEqualTo("they/them");
        assertThat(updated.visibility()).isEqualTo("internal");
        assertThat(updated.vanitySubdomainEnabled()).isFalse();
    }

    @Test
    void ownerIsolation_oneUserCannotSeeOrOverwriteAnother() {
        repo.save(new UserProfile("alice", null, "she/her", null, "Alice", "internal", false)).block();
        repo.save(new UserProfile("bob", null, "he/him", null, "Bob", "internal", false)).block();

        // bob's read only ever returns bob's row
        assertThat(repo.find("bob").block().displayName()).isEqualTo("Bob");
        // a write keyed to bob never touches alice's row
        repo.save(new UserProfile("bob", null, "he/him", null, "Bobby", "internal", false)).block();
        assertThat(repo.find("alice").block().displayName()).isEqualTo("Alice");
        assertThat(repo.find("bob").block().displayName()).isEqualTo("Bobby");
    }

    @Test
    void delete_removesOnlyOwnerRow() {
        repo.save(new UserProfile("alice", null, null, null, "Alice", "internal", false)).block();
        repo.save(new UserProfile("bob", null, null, null, "Bob", "internal", false)).block();
        repo.delete("alice").block();
        assertThat(repo.find("alice").blockOptional()).isEmpty();
        assertThat(repo.find("bob").block().displayName()).isEqualTo("Bob");
    }
}
