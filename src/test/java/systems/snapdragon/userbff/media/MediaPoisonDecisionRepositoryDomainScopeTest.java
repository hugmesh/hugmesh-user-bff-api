package systems.snapdragon.userbff.media;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import systems.snapdragon.userbff.support.TestDatabaseConfig;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * DOMAIN-SCOPE isolation for {@link MediaPoisonDecisionRepository} — the server-owned
 * AI-cloak decision is the badge + already-cloaked-repost source of truth, so a
 * cross-brand read leak would let one brand's badge speak for another's media.
 * Delineated:
 *
 * <ul>
 *   <li><b>MULTIUSER-SITUATIONAL</b> — the same owner id records decisions in two
 *       brands; each brand lists only its own.</li>
 *   <li><b>CROSS-USER</b> — the badge/repost read ({@code findByOwnerAndRef}) is
 *       owner-AND-domain scoped: a brand-X principal cannot read a brand-Y decision
 *       even with the exact {@code media_ref}; SUPERADMIN (null) can.</li>
 * </ul>
 *
 * <p>NOTE: {@code @DataR2dbcTest} reuses ONE H2 store across the methods of this
 * class, so each method uses a UNIQUE owner id to stay isolated.
 */
@DataR2dbcTest
@Import({TestDatabaseConfig.class, MediaPoisonDecisionRepository.class})
class MediaPoisonDecisionRepositoryDomainScopeTest {

    @Autowired MediaPoisonDecisionRepository repo;

    @Nested
    class MultiuserSituational {
        @Test
        void sameOwnerTwoBrands_listsOwnBrandOnly() {
            repo.record("mp-ms", "matrix", "mxc://x/1", "glaze", "protected", "cuda", "brandx").block();
            repo.record("mp-ms", "mastodon", "media-2", "glaze", "protected", "rocm", "brandy").block();

            assertThat(repo.listForOwner("mp-ms", "brandx").collectList().block())
                    .extracting(MediaPoisonDecision::mediaRef).containsExactly("mxc://x/1");
            assertThat(repo.listForOwner("mp-ms", "brandy").collectList().block())
                    .extracting(MediaPoisonDecision::mediaRef).containsExactly("media-2");
        }
    }

    @Nested
    class CrossUser {
        @Test
        void badgeRead_isOwnerAndDomainScoped() {
            // same owner + SAME media_ref string in two brands.
            repo.record("mp-cu", "matrix", "shared-ref", "glaze", "protected", "cuda", "brandx").block();
            repo.record("mp-cu", "mastodon", "shared-ref", "glaze", "degraded", "rocm", "brandy").block();

            // brandx principal reads ONLY the brandx decision for that ref.
            MediaPoisonDecision x = repo.findByOwnerAndRef("mp-cu", "shared-ref", "brandx").block();
            assertThat(x).isNotNull();
            assertThat(x.status()).isEqualTo("protected");
            assertThat(x.platform()).isEqualTo("matrix");

            // a brandx principal CANNOT see the brandy decision; a foreign brand the
            // owner has no row in returns nothing.
            assertThat(repo.findByOwnerAndRef("mp-cu", "shared-ref", "brandz").blockOptional()).isEmpty();
        }

        @Test
        void superadminBypass_seesAnyBrandDecision() {
            repo.record("mp-sa", "mastodon", "only-ref", "glaze", "degraded", "rocm", "brandy").block();
            // null domain = SUPERADMIN bypass -> the brandy decision is visible.
            MediaPoisonDecision d = repo.findByOwnerAndRef("mp-sa", "only-ref", null).block();
            assertThat(d).isNotNull();
            assertThat(d.status()).isEqualTo("degraded");
        }
    }
}
