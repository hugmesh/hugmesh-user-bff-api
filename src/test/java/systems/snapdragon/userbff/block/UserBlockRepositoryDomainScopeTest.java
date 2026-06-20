package systems.snapdragon.userbff.block;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import reactor.core.publisher.Flux;
import reactor.test.StepVerifier;
import systems.snapdragon.userbff.support.TestDatabaseConfig;

import java.time.Duration;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * DOMAIN-SCOPE isolation at the SQL layer for {@link UserBlockRepository} against H2
 * (PostgreSQL-compat) with the REAL Liquibase changelog (incl. 010-domain-scoping).
 * Delineated per the test standard:
 *
 * <ul>
 *   <li><b>MULTIUSER-SITUATIONAL</b> — the SAME owner id existing in two brands sees
 *       only their own brand's rows; the SUPERADMIN bypass (null domain) sees both.</li>
 *   <li><b>CROSS-USER</b> — the ISOLATION KEYSTONE: a brand-X principal is DENIED
 *       brand-Y data (read returns nothing, delete affects zero rows) even with a
 *       known row id; the brand-Y row is untouched.</li>
 *   <li><b>CONCURRENT</b> — two brands inserting under the same owner id at once each
 *       land in their own brand; a cross-brand delete race never removes the other
 *       brand's row.</li>
 * </ul>
 *
 * <p>NOTE: {@code @DataR2dbcTest} reuses ONE H2 store across the methods of this
 * class, so each method uses a UNIQUE owner id to stay isolated from the others
 * (the same convention as {@code UserBlockRepositoryTest}).
 */
@DataR2dbcTest
@Import({TestDatabaseConfig.class, UserBlockRepository.class})
class UserBlockRepositoryDomainScopeTest {

    @Autowired UserBlockRepository repo;

    // ── MULTIUSER-SITUATIONAL ─────────────────────────────────────────────────
    @Nested
    class MultiuserSituational {

        @Test
        void sameOwnerInTwoBrands_eachSeesOnlyOwnBrand() {
            repo.add("ms-1", "@x:evil", "matrix", "brandx").block();
            repo.add("ms-1", "@y:evil", "mastodon", "brandy").block();

            List<UserBlock> x = repo.listForOwner("ms-1", "brandx").collectList().block();
            List<UserBlock> y = repo.listForOwner("ms-1", "brandy").collectList().block();
            assertThat(x).extracting(UserBlock::target).containsExactly("@x:evil");
            assertThat(y).extracting(UserBlock::target).containsExactly("@y:evil");
        }

        @Test
        void superadminBypass_nullDomain_seesEveryBrand() {
            repo.add("ms-2", "@x:evil", "matrix", "brandx").block();
            repo.add("ms-2", "@y:evil", "mastodon", "brandy").block();

            // null domain = SUPERADMIN cross-domain bypass -> both rows.
            List<UserBlock> all = repo.listForOwner("ms-2", null).collectList().block();
            assertThat(all).extracting(UserBlock::target)
                    .containsExactlyInAnyOrder("@x:evil", "@y:evil");
        }
    }

    // ── CROSS-USER (isolation keystone) ───────────────────────────────────────
    @Nested
    class CrossUser {

        @Test
        void brandXPrincipal_cannotReadBrandYRow() {
            UserBlock yRow = repo.add("cu-1", "@y:evil", "mastodon", "brandy").block();
            // cu-1 acting from brandx sees nothing of their brandy row.
            assertThat(repo.listForOwner("cu-1", "brandx").collectList().block()).isEmpty();
            // brandy still has it.
            assertThat(repo.listForOwner("cu-1", "brandy").collectList().block())
                    .extracting(UserBlock::id).containsExactly(yRow.id());
        }

        @Test
        void brandXPrincipal_cannotDeleteBrandYRow_evenWithKnownId() {
            UserBlock yRow = repo.add("cu-2", "@y:evil", "mastodon", "brandy").block();
            // a delete scoped to brandx (the caller's brand) with the brandy row id
            // affects ZERO rows — the cross-brand row is untouched.
            assertThat(repo.delete("cu-2", yRow.id(), "brandx").block()).isEqualTo(0L);
            assertThat(repo.listForOwner("cu-2", "brandy").collectList().block()).hasSize(1);
            // the legitimate brandy-scoped delete works.
            assertThat(repo.delete("cu-2", yRow.id(), "brandy").block()).isEqualTo(1L);
        }

        @Test
        void differentOwners_sameBrand_stillOwnerIsolated() {
            UserBlock aRow = repo.add("cu-3a", "@x:evil", "matrix", "brandx").block();
            repo.add("cu-3b", "@z:evil", "matrix", "brandx").block();
            // cu-3b (same brand) cannot delete cu-3a's row.
            assertThat(repo.delete("cu-3b", aRow.id(), "brandx").block()).isEqualTo(0L);
            assertThat(repo.listForOwner("cu-3a", "brandx").collectList().block()).hasSize(1);
        }
    }

    // ── CONCURRENT ────────────────────────────────────────────────────────────
    @Nested
    class Concurrent {

        @Test
        void concurrentCrossBrandInserts_sameOwner_landInOwnBrands() {
            // 20 inserts per brand under the SAME owner id, interleaved.
            Flux<UserBlock> x = Flux.range(0, 20)
                    .flatMap(i -> repo.add("co-1", "@x" + i, "matrix", "brandx"));
            Flux<UserBlock> y = Flux.range(0, 20)
                    .flatMap(i -> repo.add("co-1", "@y" + i, "mastodon", "brandy"));
            Flux.merge(x, y).blockLast(Duration.ofSeconds(30));

            assertThat(repo.listForOwner("co-1", "brandx").collectList().block()).hasSize(20);
            assertThat(repo.listForOwner("co-1", "brandy").collectList().block()).hasSize(20);
            // and every brandx row really is brandx-scoped (none leaked to brandy view).
            assertThat(repo.listForOwner("co-1", "brandx").collectList().block())
                    .allSatisfy(b -> assertThat(b.target()).startsWith("@x"));
        }

        @Test
        void concurrentCrossBrandDeletes_neverRemoveOtherBrandRow() {
            UserBlock xRow = repo.add("co-2", "@x:evil", "matrix", "brandx").block();
            UserBlock yRow = repo.add("co-2", "@y:evil", "mastodon", "brandy").block();

            // brandx tries to delete the brandy id AND brandy deletes its own, at once.
            Flux<Long> deletes = Flux.merge(
                    repo.delete("co-2", yRow.id(), "brandx"),   // wrong brand -> 0
                    repo.delete("co-2", yRow.id(), "brandy"));  // right brand -> 1
            StepVerifier.create(deletes.reduce(0L, Long::sum))
                    .expectNext(1L)                              // exactly one effective delete
                    .verifyComplete();
            // brandx row is wholly untouched by the cross-brand attempt.
            assertThat(repo.listForOwner("co-2", "brandx").collectList().block())
                    .extracting(UserBlock::id).containsExactly(xRow.id());
        }
    }
}
