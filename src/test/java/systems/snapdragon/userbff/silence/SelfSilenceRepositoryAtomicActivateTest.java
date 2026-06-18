package systems.snapdragon.userbff.silence;

import io.r2dbc.spi.R2dbcDataIntegrityViolationException;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.data.r2dbc.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.r2dbc.core.DatabaseClient;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;
import systems.snapdragon.userbff.support.TestDatabaseConfig;

import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * ATOMIC / IDEMPOTENT activate guard for {@link SelfSilenceRepository}.
 *
 * <p>FAIL-FIRST: these tests are written to FAIL against the former
 * DELETE-then-INSERT implementation of {@link SelfSilenceRepository#activate}. That
 * implementation issued two unguarded statements (DELETE WHERE user_id, then an
 * unconditional INSERT) against a {@code user_id}-only PRIMARY KEY with NO
 * transaction / lock / ON CONFLICT, so two CONCURRENT same-subject activations can
 * interleave DELETE/DELETE then INSERT/INSERT and trip a {@code 23505} unique
 * violation — which surfaces as a 500 ({@link systems.snapdragon.userbff.web.ApiExceptionHandler}
 * has NO duplicate-key handler). A self-silence is owner-only ({@code owner ==
 * subject}), so a single user double-tapping / retrying CAN race themselves.
 *
 * <p>The fix makes {@code activate} a portable UPDATE-first / INSERT-if-absent upsert
 * (mirroring {@code NotificationPreferenceRepository.upsert}), so a re-activate is a
 * pure in-place UPDATE that never trips the PK.
 *
 * <p>{@link #sanity_rawDeleteThenInsert_isNotAtomic_underInterleave()} below PROVES
 * the race is real on this exact H2 schema (the unconditional INSERT raises a unique
 * violation when a peer INSERT has already landed) — i.e. the bug the
 * DELETE-then-INSERT {@code activate} exposed — while the CONCURRENT test proves the
 * fixed {@code activate} survives the same storm.
 *
 * <p>Delineated per the test standard:
 * <ul>
 *   <li><b>USER-SITUATIONAL (idempotency)</b> — re-activating the same subject in the
 *       same brand repeatedly never errors and converges to exactly one ACTIVE row
 *       carrying the latest window/reason.</li>
 *   <li><b>CONCURRENT-CONFLICTING (same subject)</b> — many truly-parallel same-subject
 *       activations all complete without a unique-violation / 500 and leave a single
 *       active row.</li>
 * </ul>
 *
 * <p>NOTE: {@code @DataR2dbcTest} reuses ONE H2 store across the methods of this
 * class, so each method uses a UNIQUE user id.
 */
@DataR2dbcTest
@Import({TestDatabaseConfig.class, SelfSilenceRepository.class})
class SelfSilenceRepositoryAtomicActivateTest {

    @Autowired SelfSilenceRepository repo;
    @Autowired DatabaseClient db;

    private static Instant inOneHour() {
        return Instant.now().plus(1, ChronoUnit.HOURS);
    }

    /** Presence of a subject's single row (PK on user_id) in a brand. */
    private long rowCount(String userId, String domain) {
        SelfSilence row = repo.find(userId, domain).block();
        return row == null ? 0L : 1L;
    }

    // ── SANITY: the race is REAL on this schema ───────────────────────────────
    /**
     * Demonstrates WHY the old DELETE-then-INSERT was unsafe: the unconditional INSERT
     * the old {@code activate} performed AFTER its DELETE raises a {@code 23505} unique
     * violation when a concurrent activation's INSERT has already re-created the row
     * (DELETE/DELETE then INSERT/INSERT). If this ever stops throwing, the concurrency
     * guarantee below is no longer meaningful, so we assert it explicitly.
     */
    @Test
    void sanity_rawDeleteThenInsert_isNotAtomic_underInterleave() {
        String uid = "atomic-sanity";
        Mono<Long> insert = db.sql("INSERT INTO self_silence "
                        + "(user_id, started_at, expires_at, cleared_at, reason, domain, updated_at) "
                        + "VALUES (:uid, now(), :exp, NULL, :reason, :dom, now())")
                .bind("uid", uid)
                .bind("exp", LocalDateTime.ofInstant(inOneHour(), ZoneOffset.UTC))
                .bind("reason", "r")
                .bind("dom", "default")
                .fetch().rowsUpdated();

        insert.block();   // peer's INSERT lands first (as if the racing thread won the INSERT)
        // The old activate's own INSERT (no ON CONFLICT, no UPDATE-first) now collides.
        assertThatThrownBy(insert::block)
                .isInstanceOfAny(DataIntegrityViolationException.class,
                        R2dbcDataIntegrityViolationException.class);
    }

    // ── USER-SITUATIONAL (idempotency) ────────────────────────────────────────
    @Nested
    class Idempotency {

        @Test
        void reActivatingSameSubject_neverErrors_andConvergesToOneActiveRow() {
            String uid = "atomic-idem";
            for (int i = 0; i < 20; i++) {
                SelfSilence written = repo.activate(uid, inOneHour().plusSeconds(i),
                        "reason-" + i, "brandx").block();
                assertThat(written).as("activate must always return the freshly-written row").isNotNull();
            }
            assertThat(rowCount(uid, "brandx")).isEqualTo(1L);
            SelfSilence latest = repo.find(uid, "brandx").block();
            assertThat(latest).isNotNull();
            assertThat(latest.reason()).isEqualTo("reason-19");
            assertThat(latest.clearedAt()).as("a re-activate must leave the row ACTIVE (cleared_at NULL)").isNull();
            assertThat(latest.active()).isTrue();
        }

        @Test
        void reActivatingAfterClear_startsAFreshActiveWindow() {
            String uid = "atomic-reactivate-after-clear";
            repo.activate(uid, inOneHour(), "first", "brandx").block();
            assertThat(repo.clear(uid, "brandx").block()).isEqualTo(1L);
            assertThat(repo.find(uid, "brandx").block().clearedAt()).isNotNull();

            SelfSilence reborn = repo.activate(uid, inOneHour(), "second", "brandx").block();
            assertThat(reborn).isNotNull();
            assertThat(reborn.clearedAt()).isNull();
            assertThat(reborn.reason()).isEqualTo("second");
            assertThat(reborn.active()).isTrue();
            assertThat(rowCount(uid, "brandx")).isEqualTo(1L);
        }
    }

    // ── CONCURRENT-CONFLICTING (same subject) ─────────────────────────────────
    @Nested
    class ConcurrentSameSubject {

        /**
         * The KEYSTONE fail-first proof: fire many TRULY-PARALLEL activations for the
         * SAME subject in the SAME brand (each subscribed on a distinct parallel-worker
         * thread, repeated over several rounds), with a row already present so the racing
         * sequences overlap on a live row. The old DELETE-then-INSERT interleaves into a
         * 23505 unique violation; the atomic upsert lets every activation complete and
         * leaves exactly one active row.
         */
        @Test
        void concurrentSameSubjectActivations_neverRaiseUniqueViolation_oneActiveRow() {
            String uid = "atomic-conc";
            int fanout = 64;
            int rounds = 8;

            // Seed a live row so DELETE-then-INSERT sequences have something to race over.
            repo.activate(uid, inOneHour(), "seed", "brandx").block();

            AtomicReference<Throwable> firstError = new AtomicReference<>();

            for (int round = 0; round < rounds; round++) {
                final int r = round;
                List<SelfSilence> results = Flux.range(0, fanout)
                        .flatMap(i -> repo.activate(uid, inOneHour().plusSeconds(i),
                                        "r-" + r + "-" + i, "brandx")
                                // force genuine cross-thread overlap at the statement boundary
                                .subscribeOn(Schedulers.parallel())
                                .onErrorResume(t -> {
                                    firstError.compareAndSet(null, t);
                                    return Mono.empty();
                                }), fanout)
                        .collectList()
                        .block(Duration.ofSeconds(60));
                assertThat(results).isNotNull();
            }

            // No activation may have surfaced a unique-violation / any error.
            assertThat(firstError.get())
                    .as("concurrent same-subject activate must never raise a unique violation / 500")
                    .isNull();

            // Exactly one row survives (PK), and it is active.
            assertThat(rowCount(uid, "brandx")).isEqualTo(1L);
            assertThat(repo.find(uid, "brandx").block().active()).isTrue();
        }

        /**
         * Same race on a BRAND-NEW subject (no pre-existing row): every concurrent
         * activation either UPDATEs or does the single conditional INSERT; the result
         * must still be one active row with no error surfacing.
         */
        @Test
        void concurrentFirstActivationsOfFreshSubject_convergeToOneActiveRow() {
            String uid = "atomic-conc-fresh";
            int fanout = 48;

            AtomicReference<Throwable> firstError = new AtomicReference<>();
            Flux.range(0, fanout)
                    .flatMap(i -> repo.activate(uid, inOneHour().plusSeconds(i), "r-" + i, "brandx")
                            .subscribeOn(Schedulers.parallel())
                            .onErrorResume(t -> {
                                firstError.compareAndSet(null, t);
                                return Mono.empty();
                            }), fanout)
                    .blockLast(Duration.ofSeconds(60));

            assertThat(firstError.get())
                    .as("concurrent first-activations of a fresh subject must not 500")
                    .isNull();
            assertThat(rowCount(uid, "brandx")).isEqualTo(1L);
            assertThat(repo.find(uid, "brandx").block().active()).isTrue();
        }
    }
}
