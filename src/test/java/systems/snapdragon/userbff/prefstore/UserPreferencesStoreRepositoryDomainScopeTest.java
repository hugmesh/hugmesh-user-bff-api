package systems.snapdragon.userbff.prefstore;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.data.r2dbc.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import reactor.core.publisher.Flux;
import systems.snapdragon.userbff.support.TestDatabaseConfig;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * DOMAIN-SCOPE + owner isolation for {@link UserPreferencesStoreRepository} over the
 * real Liquibase-applied H2 schema. The durable preferences store carries the per-user
 * AI-poison default the compose toggle persists, so a cross-brand / cross-owner read or
 * write leak would let one brand (or one user) speak for another's durable preference.
 * Delineated per the test standard:
 *
 * <ul>
 *   <li><b>MULTIUSER-SITUATIONAL</b> — the SAME owner id holds a SEPARATE durable value
 *       per brand (domain is in the PK); each brand reads only its own.</li>
 *   <li><b>CROSS-USER</b> — owner isolation (owner A cannot read/affect owner B's row)
 *       AND brand isolation (a brand-X read/upsert/delete cannot touch a brand-Y row,
 *       even at the SAME owner+key); SUPERADMIN (null domain) crosses both.</li>
 *   <li><b>CONCURRENT</b> — concurrent same-owner upserts of the SAME key in one brand
 *       converge to a single durable row (PK upsert, no duplicate); cross-brand
 *       concurrent upserts each land in their own brand.</li>
 * </ul>
 *
 * <p>NOTE: {@code @DataR2dbcTest} reuses ONE H2 store across the methods of this class,
 * so each method uses a UNIQUE owner id to stay isolated.
 */
@DataR2dbcTest
@Import({TestDatabaseConfig.class, UserPreferencesStoreRepository.class})
class UserPreferencesStoreRepositoryDomainScopeTest {

    @Autowired UserPreferencesStoreRepository repo;

    private static final String K = "media.poison.default";

    // ── MULTIUSER-SITUATIONAL ─────────────────────────────────────────────────
    @Nested
    class MultiuserSituational {
        @Test
        void sameOwnerTwoBrands_separateDurableValuePerBrand() {
            repo.upsert("ps-ms", K, "glaze", "brandx").block();
            repo.upsert("ps-ms", K, "nightshade", "brandy").block();

            assertThat(repo.find("ps-ms", K, "brandx").block()).isEqualTo("glaze");
            assertThat(repo.find("ps-ms", K, "brandy").block()).isEqualTo("nightshade");
            assertThat(repo.findAll("ps-ms", "brandx").block()).containsExactly(java.util.Map.entry(K, "glaze"));
            assertThat(repo.findAll("ps-ms", "brandy").block()).containsExactly(java.util.Map.entry(K, "nightshade"));
        }

        @Test
        void upsertIsIdempotentUpdate_oneRowPerOwnerKeyBrand() {
            repo.upsert("ps-up", K, "glaze", "brandx").block();
            repo.upsert("ps-up", K, "light", "brandx").block();   // same owner+key+brand => UPDATE
            assertThat(repo.find("ps-up", K, "brandx").block()).isEqualTo("light");
            assertThat(repo.findAll("ps-up", "brandx").block()).hasSize(1);
        }
    }

    // ── CROSS-USER ────────────────────────────────────────────────────────────
    @Nested
    class CrossUser {
        @Test
        void ownerIsolation_aCannotReadOrAffectB() {
            repo.upsert("ps-cu-a", K, "glaze", "brandx").block();
            repo.upsert("ps-cu-b", K, "none", "brandx").block();

            // owner A reads ONLY its own row; B's value is invisible.
            assertThat(repo.find("ps-cu-a", K, "brandx").block()).isEqualTo("glaze");
            assertThat(repo.find("ps-cu-b", K, "brandx").block()).isEqualTo("none");

            // owner A deleting cannot remove owner B's row.
            repo.delete("ps-cu-a", K, "brandx").block();
            assertThat(repo.find("ps-cu-a", K, "brandx").blockOptional()).isEmpty();
            assertThat(repo.find("ps-cu-b", K, "brandx").block()).isEqualTo("none");
        }

        @Test
        void brandIsolation_brandXReadWriteCannotTouchBrandYRow() {
            // SAME owner + SAME key in two brands.
            repo.upsert("ps-cu-x", K, "glaze", "brandx").block();
            repo.upsert("ps-cu-x", K, "nightshade", "brandy").block();

            // a brandz scope (owner has no row there) reads nothing.
            assertThat(repo.find("ps-cu-x", K, "brandz").blockOptional()).isEmpty();

            // a brandx UPSERT must not overwrite the brandy value.
            repo.upsert("ps-cu-x", K, "light", "brandx").block();
            assertThat(repo.find("ps-cu-x", K, "brandx").block()).isEqualTo("light");
            assertThat(repo.find("ps-cu-x", K, "brandy").block()).isEqualTo("nightshade");

            // a brandx DELETE must not remove the brandy row.
            repo.delete("ps-cu-x", K, "brandx").block();
            assertThat(repo.find("ps-cu-x", K, "brandx").blockOptional()).isEmpty();
            assertThat(repo.find("ps-cu-x", K, "brandy").block()).isEqualTo("nightshade");
        }

        @Test
        void superadminBypass_readsEveryBrandsRow() {
            repo.upsert("ps-sa", K, "glaze", "brandx").block();
            repo.upsert("ps-sa", "ui.theme", "dark", "brandy").block();
            // null domain = SUPERADMIN cross-domain bypass: both brands' rows are visible.
            assertThat(repo.findAll("ps-sa", null).block())
                    .containsEntry(K, "glaze").containsEntry("ui.theme", "dark");
        }
    }

    // ── CONCURRENT ────────────────────────────────────────────────────────────
    @Nested
    class Concurrent {
        @Test
        void concurrentSameKeySameBrand_convergeToSingleRow() {
            // many concurrent upserts of the SAME owner+key+brand: the PK upsert must
            // never produce a duplicate row (no find-then-insert race window).
            Flux.range(0, 30)
                    .flatMap(i -> repo.upsert("ps-conc", K, i % 2 == 0 ? "glaze" : "light", "brandx"))
                    .blockLast(Duration.ofSeconds(30));

            assertThat(repo.findAll("ps-conc", "brandx").block()).hasSize(1);
            assertThat(repo.find("ps-conc", K, "brandx").block()).isIn("glaze", "light");
        }

        @Test
        void concurrentCrossBrandUpserts_landInOwnBrands() {
            Flux.merge(
                    Flux.range(0, 15).flatMap(i -> repo.upsert("ps-conc2", "k" + i, "glaze", "brandx")),
                    Flux.range(0, 15).flatMap(i -> repo.upsert("ps-conc2", "k" + i, "none", "brandy")))
                    .blockLast(Duration.ofSeconds(30));

            assertThat(repo.findAll("ps-conc2", "brandx").block()).hasSize(15)
                    .allSatisfy((k, v) -> assertThat(v).isEqualTo("glaze"));
            assertThat(repo.findAll("ps-conc2", "brandy").block()).hasSize(15)
                    .allSatisfy((k, v) -> assertThat(v).isEqualTo("none"));
        }
    }
}
