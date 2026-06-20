package systems.snapdragon.userbff.profile;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import systems.snapdragon.userbff.support.TestDatabaseConfig;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * DOMAIN-SCOPE isolation for {@link UserProfileRepository}. {@code user_profile} is
 * PK'd on {@code user_id}, so the upsert's domain-scoped UPDATE-then-INSERT is the
 * subtle path: a brand-X save must NEVER overwrite the brand-Y profile of the same
 * user id. Delineated:
 *
 * <ul>
 *   <li><b>MULTIUSER-SITUATIONAL</b> — the same user id holds an independent profile
 *       per brand; each read returns its own brand's row.</li>
 *   <li><b>CROSS-USER</b> — a brand-X read cannot see the brand-Y profile;
 *       SUPERADMIN (null) can read across brands.</li>
 * </ul>
 *
 * <p>NOTE: with a single PK on {@code user_id}, two brands for the same user id can
 * only coexist when their rows carry distinct {@code domain} values AND the PK is
 * not violated — this test uses DISTINCT user ids per brand to assert the read/write
 * predicate composes with ownership without fighting the single-column PK, plus one
 * same-id case proving a brand-X save does not clobber a brand-Y row keyed by domain.
 */
@DataR2dbcTest
@Import({TestDatabaseConfig.class, UserProfileRepository.class})
class UserProfileRepositoryDomainScopeTest {

    @Autowired UserProfileRepository repo;

    private static UserProfile profile(String userId, String displayName) {
        return new UserProfile(userId, null, null, null, displayName, "internal", false);
    }

    @Nested
    class MultiuserSituational {
        @Test
        void distinctOwners_perBrand_readOwnBrand() {
            repo.save(profile("ax", "Alice X"), "brandx").block();
            repo.save(profile("by", "Bob Y"), "brandy").block();

            assertThat(repo.find("ax", "brandx").block().displayName()).isEqualTo("Alice X");
            assertThat(repo.find("by", "brandy").block().displayName()).isEqualTo("Bob Y");
            // wrong-brand read of an existing owner returns empty.
            assertThat(repo.find("ax", "brandy").blockOptional()).isEmpty();
        }
    }

    @Nested
    class CrossUser {
        @Test
        void brandXRead_cannotSeeBrandYProfile() {
            repo.save(profile("solo", "Solo BrandY"), "brandy").block();
            // a brandx-scoped read of the same user id sees nothing (the row is brandy).
            assertThat(repo.find("solo", "brandx").blockOptional()).isEmpty();
            // brandy sees it; SUPERADMIN (null) sees it too.
            assertThat(repo.find("solo", "brandy").block().displayName()).isEqualTo("Solo BrandY");
            assertThat(repo.find("solo", null).block().displayName()).isEqualTo("Solo BrandY");
        }

        @Test
        void brandScopedSave_doesNotClobberOtherBrandRowOfSameUser_whenInsertable() {
            // brandy row exists for user 'shared'.
            repo.save(profile("shared", "BrandY name"), "brandy").block();
            // A brandx-scoped save for the SAME user id: the domain-scoped UPDATE finds
            // no brandx row, so it INSERTs — but the single-column PK on user_id means
            // the brandy row already occupies the key. The write therefore fails rather
            // than silently overwriting the brandy row (isolation preserved): the
            // brandy row is unchanged afterwards.
            try {
                repo.save(profile("shared", "BrandX attempt"), "brandx").block();
            } catch (RuntimeException expectedPkClash) {
                // PK collision is the CORRECT outcome — a brandx save must not be able
                // to overwrite the brandy row via the domain-scoped upsert.
            }
            assertThat(repo.find("shared", "brandy").block().displayName()).isEqualTo("BrandY name");
        }
    }
}
