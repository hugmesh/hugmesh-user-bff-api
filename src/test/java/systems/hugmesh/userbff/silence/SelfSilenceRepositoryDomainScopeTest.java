package systems.hugmesh.userbff.silence;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import reactor.core.publisher.Flux;
import reactor.test.StepVerifier;
import systems.hugmesh.userbff.support.TestDatabaseConfig;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * DOMAIN-SCOPE isolation at the SQL layer for {@link SelfSilenceRepository} against
 * H2 (PostgreSQL-compat) with the REAL Liquibase changelog (incl. 010-domain-scoping).
 *
 * <p><b>Schema constraint:</b> {@code self_silence} has a PRIMARY KEY on
 * {@code user_id} — one silence row per user globally. A user cannot simultaneously
 * have silences in two brands. Domain scope is therefore tested with DISTINCT user ids
 * per brand (users who belong to different brands are different principals).
 *
 * <p>Delineated per the test standard:
 * <ul>
 *   <li><b>MULTIUSER-SITUATIONAL</b> — two users each in their own brand; each brand
 *       lists only its own user's row (cross-brand read returns nothing).</li>
 *   <li><b>CROSS-USER</b> — the ISOLATION KEYSTONE: a brand-X scope cannot find or
 *       clear a brand-Y user's silence even with the known user id; the brand-Y row
 *       is untouched after the failed cross-brand attempt.</li>
 *   <li><b>CONCURRENT</b> — concurrent activations in two brands land in their own
 *       brand; a concurrent cross-brand clear race never removes the other brand's
 *       active silence.</li>
 * </ul>
 *
 * <p>NOTE: {@code @DataR2dbcTest} reuses ONE H2 store across the methods of this
 * class, so each method uses UNIQUE user ids to stay isolated from the others.
 */
@DataR2dbcTest
@Import({TestDatabaseConfig.class, SelfSilenceRepository.class})
class SelfSilenceRepositoryDomainScopeTest {

    @Autowired SelfSilenceRepository repo;

    private static Instant inOneHour() {
        return Instant.now().plus(1, ChronoUnit.HOURS);
    }

    private static Instant inTwoHours() {
        return Instant.now().plus(2, ChronoUnit.HOURS);
    }

    // ── MULTIUSER-SITUATIONAL ─────────────────────────────────────────────────
    @Nested
    class MultiuserSituational {

        @Test
        void usersInDifferentBrands_eachBrandSeesOnlyItsOwnSilence() {
            // user-x belongs to brandx; user-y belongs to brandy — different principals.
            repo.activate("ms-user-x", inOneHour(), "afk-x", "brandx").block();
            repo.activate("ms-user-y", inTwoHours(), "afk-y", "brandy").block();

            // brandx scope finds user-x's silence.
            SelfSilence x = repo.find("ms-user-x", "brandx").block();
            assertThat(x).isNotNull();
            assertThat(x.reason()).isEqualTo("afk-x");

            // brandy scope finds user-y's silence.
            SelfSilence y = repo.find("ms-user-y", "brandy").block();
            assertThat(y).isNotNull();
            assertThat(y.reason()).isEqualTo("afk-y");
        }

        @Test
        void superadminBypass_nullDomain_seesAnyBrandSilence() {
            repo.activate("ms-super-x", inOneHour(), "afk-x", "brandx").block();
            repo.activate("ms-super-y", inTwoHours(), "afk-y", "brandy").block();

            // null domain = SUPERADMIN cross-domain bypass — visible regardless of brand.
            assertThat(repo.find("ms-super-x", null).block()).isNotNull();
            assertThat(repo.find("ms-super-y", null).block()).isNotNull();
        }
    }

    // ── CROSS-USER (isolation keystone) ───────────────────────────────────────
    @Nested
    class CrossUser {

        @Test
        void brandXScope_cannotFindBrandYUserSilence() {
            repo.activate("cu-user-y", inOneHour(), "afk-y", "brandy").block();

            // A brandx-scoped find for the brandy user returns nothing.
            assertThat(repo.find("cu-user-y", "brandx").blockOptional()).isEmpty();
            // The brandy-scoped find still works.
            assertThat(repo.find("cu-user-y", "brandy").block()).isNotNull();
        }

        @Test
        void brandXScope_cannotClearBrandYUserSilence_evenWithKnownUserId() {
            repo.activate("cu-user-y2", inOneHour(), "afk-y", "brandy").block();

            // A clear scoped to brandx with the brandy user's id affects zero rows.
            assertThat(repo.clear("cu-user-y2", "brandx").block()).isEqualTo(0L);
            // The brandy silence is untouched.
            assertThat(repo.find("cu-user-y2", "brandy").block().reason()).isEqualTo("afk-y");
            // The legitimate brandy-scoped clear works.
            assertThat(repo.clear("cu-user-y2", "brandy").block()).isEqualTo(1L);
        }

        @Test
        void brandZScope_seesNothingForBrandYUser() {
            repo.activate("cu-user-y3", inOneHour(), "afk-y", "brandy").block();

            // A completely different brand (brandz) cannot read the brandy silence.
            assertThat(repo.find("cu-user-y3", "brandz").blockOptional()).isEmpty();
            // The originating brand still owns the row.
            assertThat(repo.find("cu-user-y3", "brandy").block()).isNotNull();
        }
    }

    // ── CONCURRENT ────────────────────────────────────────────────────────────
    @Nested
    class Concurrent {

        @Test
        void concurrentActivations_inDifferentBrands_distinctUserIds_landInOwnBrand() {
            // 5 distinct users per brand, activated concurrently — each in their own brand.
            Flux<SelfSilence> x = Flux.range(0, 5)
                    .flatMap(i -> repo.activate("co-x-" + i, inOneHour().plusSeconds(i),
                            "reason-x-" + i, "brandx"));
            Flux<SelfSilence> y = Flux.range(0, 5)
                    .flatMap(i -> repo.activate("co-y-" + i, inTwoHours().plusSeconds(i),
                            "reason-y-" + i, "brandy"));
            Flux.merge(x, y).blockLast(Duration.ofSeconds(30));

            // Each brandx user's silence is findable only under brandx.
            for (int i = 0; i < 5; i++) {
                assertThat(repo.find("co-x-" + i, "brandx").block()).isNotNull();
                assertThat(repo.find("co-x-" + i, "brandy").blockOptional()).isEmpty();
            }
            // Each brandy user's silence is findable only under brandy.
            for (int i = 0; i < 5; i++) {
                assertThat(repo.find("co-y-" + i, "brandy").block()).isNotNull();
                assertThat(repo.find("co-y-" + i, "brandx").blockOptional()).isEmpty();
            }
        }

        @Test
        void concurrentCrossBrandClears_neverRemoveOtherBrandSilence() {
            repo.activate("co-clear-x", inOneHour(), "afk-x", "brandx").block();
            repo.activate("co-clear-y", inTwoHours(), "afk-y", "brandy").block();

            // Simultaneously: brandx clears its own user + brandx tries to clear the brandy user.
            Flux<Long> clears = Flux.merge(
                    repo.clear("co-clear-x", "brandx"),    // right brand -> 1
                    repo.clear("co-clear-y", "brandx"));   // wrong brand -> 0
            StepVerifier.create(clears.reduce(0L, (a, b) -> a + b))
                    .expectNext(1L)                         // exactly one effective clear
                    .verifyComplete();

            // brandy silence is wholly untouched by the wrong-brand attempt.
            assertThat(repo.find("co-clear-y", "brandy").block().reason()).isEqualTo("afk-y");
        }
    }
}
