package net.hugmesh.userbff.notification;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;
import net.hugmesh.commons.testsupport.PostgresTestSupport;
import net.hugmesh.userbff.support.PostgresSliceTestConfig;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * DOMAIN-SCOPE + owner isolation for {@link UserNotificationRepository} over the real
 * Liquibase-applied H2 schema. The in-app FLOOR inbox is owner+domain scoped, so a
 * cross-brand / cross-owner read or mark-read leak would let one user see (or silence)
 * another's notification. PR1 ships dark; rows are seeded via the package-private
 * {@code insertForTest} (the real writer is the later actions reconciler). Delineated
 * per the test standard:
 *
 * <ul>
 *   <li><b>MULTIUSER-SITUATIONAL</b> — the SAME owner id has SEPARATE notifications per
 *       brand; each brand lists only its own, newest-first.</li>
 *   <li><b>CROSS-USER</b> — owner A cannot list/mark-read owner B's notification; a
 *       brand-X list/mark cannot touch a brand-Y row; SUPERADMIN (null domain) crosses
 *       both.</li>
 * </ul>
 *
 * <p>NOTE: ONE shared H2 store across the class methods — each method uses a UNIQUE
 * owner id.
 */
@DataR2dbcTest
@ActiveProfiles("test")
@Import({PostgresSliceTestConfig.class, UserNotificationRepository.class})
class UserNotificationRepositoryDomainScopeTest extends PostgresTestSupport {

    @Autowired UserNotificationRepository repo;

    private static final String C = NotificationCategory.ROLE_CHANGE;

    // ── MULTIUSER-SITUATIONAL ─────────────────────────────────────────────────
    @Nested
    class MultiuserSituational {
        @Test
        void sameOwnerTwoBrands_eachBrandSeesOnlyItsOwn() {
            repo.insertForTest("un-ms", C, "x-title", "b", "brandx").block();
            repo.insertForTest("un-ms", C, "y-title", "b", "brandy").block();

            List<UserNotification> x = repo.listForOwner("un-ms", "brandx", 50).collectList().block();
            List<UserNotification> y = repo.listForOwner("un-ms", "brandy", 50).collectList().block();
            assertThat(x).extracting(UserNotification::title).containsExactly("x-title");
            assertThat(y).extracting(UserNotification::title).containsExactly("y-title");
        }

        @Test
        void listIsNewestFirst_andCapped() {
            for (int i = 0; i < 5; i++) {
                repo.insertForTest("un-order", C, "t" + i, null, "brandx").block();
            }
            List<UserNotification> capped = repo.listForOwner("un-order", "brandx", 2).collectList().block();
            assertThat(capped).hasSize(2);   // limit honoured
        }

        @Test
        void listClampsOverCapLimit() {
            repo.insertForTest("un-clamp", C, "t", null, "brandx").block();
            // an over-cap limit clamps to MAX_PAGE (no error, no unbounded pull).
            assertThat(repo.listForOwner("un-clamp", "brandx", 100_000).collectList().block()).hasSize(1);
        }
    }

    // ── CROSS-USER ────────────────────────────────────────────────────────────
    @Nested
    class CrossUser {
        @Test
        void ownerIsolation_aCannotListOrMarkB() {
            String bId = repo.insertForTest("un-cu-b", C, "b-note", null, "brandx").block();
            repo.insertForTest("un-cu-a", C, "a-note", null, "brandx").block();

            // A lists only its own.
            assertThat(repo.listForOwner("un-cu-a", "brandx", 50).collectList().block())
                    .extracting(UserNotification::title).containsExactly("a-note");

            // A cannot mark B's notification read (0 rows updated == not A's row).
            assertThat(repo.markRead(bId, "un-cu-a", "brandx").block()).isEqualTo(0L);
            // B's row is still unread.
            assertThat(repo.existsForOwner(bId, "un-cu-b", "brandx").block()).isTrue();
            UserNotification bRow = repo.listForOwner("un-cu-b", "brandx", 50).collectList().block().get(0);
            assertThat(bRow.readAt()).isNull();
            // and A cannot even see B's row exists under A's owner.
            assertThat(repo.existsForOwner(bId, "un-cu-a", "brandx").block()).isFalse();
        }

        @Test
        void brandIsolation_brandXMarkCannotTouchBrandYRow() {
            String yId = repo.insertForTest("un-cu-x", C, "y-note", null, "brandy").block();

            // a brandx scope cannot mark the brandy row (0 rows; not in scope).
            assertThat(repo.markRead(yId, "un-cu-x", "brandx").block()).isEqualTo(0L);
            assertThat(repo.existsForOwner(yId, "un-cu-x", "brandx").block()).isFalse();
            // the brandy scope can.
            assertThat(repo.markRead(yId, "un-cu-x", "brandy").block()).isEqualTo(1L);
        }

        @Test
        void markRead_ownRow_marksReadAndIsIdempotent() {
            String id = repo.insertForTest("un-mark", C, "note", null, "brandx").block();
            assertThat(repo.markRead(id, "un-mark", "brandx").block()).isEqualTo(1L);  // marked
            // a re-mark updates 0 rows (already read) but the row still exists for the owner.
            assertThat(repo.markRead(id, "un-mark", "brandx").block()).isEqualTo(0L);
            assertThat(repo.existsForOwner(id, "un-mark", "brandx").block()).isTrue();
        }

        @Test
        void superadminBypass_listsEveryBrandsRow() {
            repo.insertForTest("un-sa", C, "x-note", null, "brandx").block();
            repo.insertForTest("un-sa", C, "y-note", null, "brandy").block();
            // null domain = SUPERADMIN cross-domain bypass: both brands' rows are visible.
            assertThat(repo.listForOwner("un-sa", null, 50).collectList().block())
                    .extracting(UserNotification::title)
                    .containsExactlyInAnyOrder("x-note", "y-note");
        }
    }
}
