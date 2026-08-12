package net.hugmesh.userbff.notification;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import reactor.core.publisher.Flux;
import net.hugmesh.userbff.support.TestDatabaseConfig;

import java.time.Duration;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * DOMAIN-SCOPE + owner isolation for {@link NotificationPreferenceRepository} over the
 * real Liquibase-applied H2 schema. The per-category preferences mirror 011 exactly
 * (domain in the PK), so a cross-brand / cross-owner read or write leak would let one
 * brand (or user) speak for another's notification opt-out. Delineated per the test
 * standard:
 *
 * <ul>
 *   <li><b>MULTIUSER-SITUATIONAL</b> — the SAME owner id holds a SEPARATE durable
 *       per-category value per brand (domain is in the PK); each brand reads only its
 *       own.</li>
 *   <li><b>CROSS-USER</b> — owner isolation (owner A cannot read/affect owner B's row)
 *       AND brand isolation (a brand-X read/upsert cannot touch a brand-Y row, even at
 *       the SAME owner+category); SUPERADMIN (null domain) crosses both.</li>
 *   <li><b>CONCURRENT</b> — concurrent same-owner upserts of the SAME category in one
 *       brand converge to a single durable row (PK upsert, no duplicate).</li>
 * </ul>
 *
 * <p>NOTE: ONE shared H2 store across the class methods — each method uses a UNIQUE
 * owner id.
 */
@DataR2dbcTest
@Import({TestDatabaseConfig.class, NotificationPreferenceRepository.class})
class NotificationPreferenceRepositoryDomainScopeTest {

    @Autowired NotificationPreferenceRepository repo;

    private static final String C = NotificationCategory.ROLE_CHANGE;

    // ── MULTIUSER-SITUATIONAL ─────────────────────────────────────────────────
    @Nested
    class MultiuserSituational {
        @Test
        void sameOwnerTwoBrands_separateDurableValuePerBrand() {
            repo.upsert("np-ms", C, false, "brandx").block();
            repo.upsert("np-ms", C, true, "brandy").block();

            assertThat(repo.findAll("np-ms", "brandx").block()).containsExactly(Map.entry(C, false));
            assertThat(repo.findAll("np-ms", "brandy").block()).containsExactly(Map.entry(C, true));
        }

        @Test
        void upsertIsIdempotentUpdate_oneRowPerOwnerCategoryBrand() {
            repo.upsert("np-up", C, false, "brandx").block();
            repo.upsert("np-up", C, true, "brandx").block();   // same owner+cat+brand => UPDATE
            assertThat(repo.findAll("np-up", "brandx").block()).containsExactly(Map.entry(C, true));
        }
    }

    // ── CROSS-USER ────────────────────────────────────────────────────────────
    @Nested
    class CrossUser {
        @Test
        void ownerIsolation_aCannotReadOrAffectB() {
            repo.upsert("np-cu-a", C, false, "brandx").block();
            repo.upsert("np-cu-b", C, true, "brandx").block();

            assertThat(repo.findAll("np-cu-a", "brandx").block()).containsExactly(Map.entry(C, false));
            assertThat(repo.findAll("np-cu-b", "brandx").block()).containsExactly(Map.entry(C, true));

            // A's upsert cannot change B's row.
            repo.upsert("np-cu-a", C, true, "brandx").block();
            assertThat(repo.findAll("np-cu-b", "brandx").block()).containsExactly(Map.entry(C, true));
        }

        @Test
        void brandIsolation_brandXWriteCannotTouchBrandYRow() {
            repo.upsert("np-cu-x", C, false, "brandx").block();
            repo.upsert("np-cu-x", C, true, "brandy").block();

            // a brandz scope (owner has no row) reads nothing.
            assertThat(repo.findAll("np-cu-x", "brandz").block()).isEmpty();

            // a brandx UPSERT must not overwrite the brandy value.
            repo.upsert("np-cu-x", C, true, "brandx").block();
            assertThat(repo.findAll("np-cu-x", "brandx").block()).containsExactly(Map.entry(C, true));
            assertThat(repo.findAll("np-cu-x", "brandy").block()).containsExactly(Map.entry(C, true));
            repo.upsert("np-cu-x", C, false, "brandy").block();
            assertThat(repo.findAll("np-cu-x", "brandx").block()).containsExactly(Map.entry(C, true));
            assertThat(repo.findAll("np-cu-x", "brandy").block()).containsExactly(Map.entry(C, false));
        }

        @Test
        void superadminBypass_readsEveryBrandsRow() {
            repo.upsert("np-sa", NotificationCategory.ROLE_CHANGE, false, "brandx").block();
            repo.upsert("np-sa", NotificationCategory.INFRA_IMPACTING, false, "brandy").block();
            // null domain = SUPERADMIN cross-domain bypass: both brands' rows are visible.
            assertThat(repo.findAll("np-sa", null).block())
                    .containsEntry(NotificationCategory.ROLE_CHANGE, false)
                    .containsEntry(NotificationCategory.INFRA_IMPACTING, false);
        }
    }

    // ── CONCURRENT ────────────────────────────────────────────────────────────
    @Nested
    class Concurrent {
        @Test
        void concurrentSameCategorySameBrand_convergeToSingleRow() {
            Flux.range(0, 30)
                    .flatMap(i -> repo.upsert("np-conc", C, i % 2 == 0, "brandx"))
                    .blockLast(Duration.ofSeconds(30));

            assertThat(repo.findAll("np-conc", "brandx").block()).hasSize(1);
        }
    }
}
