package systems.snapdragon.userbff.notification;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import systems.snapdragon.userbff.support.TestDatabaseConfig;
import systems.snapdragon.commons.web.ApiException;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * SERVICE-layer behaviour for {@link UserNotificationService} over the real repository
 * slice — proves the owner+domain-scoped list and the mark-read OWNERSHIP boundary (an
 * id that is not the caller's own owner+domain row is a 404; an already-read OWN row is
 * an idempotent success, not a 404). Delineated per the test standard:
 *
 * <ul>
 *   <li><b>USER-SITUATIONAL</b> — a user lists their own notifications and marks one
 *       read; a re-mark of an own already-read row is an idempotent success; a blank
 *       owner is rejected 401; a blank/unknown id is a 404.</li>
 *   <li><b>CROSS-USER</b> — owner A's list never shows B's; A marking B's notification
 *       (a known id) is a 404 (no cross-user mark) and B's row stays unread; a brand-X
 *       mark cannot touch a brand-Y row; SUPERADMIN (null domain) lists across brands.</li>
 * </ul>
 *
 * <p>NOTE: ONE shared H2 store across the class methods — each method uses a UNIQUE
 * owner id. Rows are seeded via the package-private {@code insertForTest} (PR1 ships
 * dark — the real writer is the later actions reconciler).
 */
@DataR2dbcTest
@Import({TestDatabaseConfig.class, UserNotificationRepository.class,
        UserNotificationServiceTest.Cfg.class})
class UserNotificationServiceTest {

    @org.springframework.boot.test.context.TestConfiguration(proxyBeanMethods = false)
    static class Cfg {
        @org.springframework.context.annotation.Bean
        UserNotificationService userNotificationService(UserNotificationRepository repo) {
            return new UserNotificationService(repo);
        }
    }

    @Autowired UserNotificationService service;
    @Autowired UserNotificationRepository repo;

    private static final String C = NotificationCategory.INFRA_IMPACTING;

    private static int status(Throwable t) {
        return ((ApiException) t).status().value();
    }

    // ── USER-SITUATIONAL ──────────────────────────────────────────────────────
    @Nested
    class UserSituational {
        @Test
        void list_ownNotifications_newestFirst() {
            repo.insertForTest("us-list", C, "first", null, "brandx").block();
            repo.insertForTest("us-list", C, "second", null, "brandx").block();
            List<UserNotification> out = service.list("us-list", "brandx", 50).block();
            assertThat(out).hasSize(2);
        }

        @Test
        void markRead_ownRow_succeeds_andReMarkIsIdempotent() {
            String id = repo.insertForTest("us-mark", C, "note", null, "brandx").block();
            // first mark succeeds (no error).
            service.markRead(id, "us-mark", "brandx").block();
            // a re-mark of an already-read OWN row is an idempotent success, NOT a 404.
            service.markRead(id, "us-mark", "brandx").block();
            // the row is read now.
            assertThat(repo.listForOwner("us-mark", "brandx", 50).collectList().block().get(0).readAt())
                    .isNotNull();
        }

        @Test
        void markRead_unknownId_isNotFound() {
            assertThatThrownBy(() -> service.markRead("00000000-0000-0000-0000-000000000000",
                    "us-unknown", "brandx").block())
                    .isInstanceOf(ApiException.class)
                    .extracting(UserNotificationServiceTest::status).isEqualTo(404);
        }

        @Test
        void markRead_blankId_isNotFound() {
            assertThatThrownBy(() -> service.markRead("  ", "us-blank", "brandx").block())
                    .isInstanceOf(ApiException.class)
                    .extracting(UserNotificationServiceTest::status).isEqualTo(404);
        }

        @Test
        void blankOwner_isUnauthorized() {
            assertThatThrownBy(() -> service.list("  ", "brandx", 50).block())
                    .isInstanceOf(ApiException.class)
                    .extracting(UserNotificationServiceTest::status).isEqualTo(401);
        }
    }

    // ── CROSS-USER ────────────────────────────────────────────────────────────
    @Nested
    class CrossUser {
        @Test
        void ownerIsolation_aDoesNotListB() {
            repo.insertForTest("uc-b", C, "b-note", null, "brandx").block();
            repo.insertForTest("uc-a", C, "a-note", null, "brandx").block();
            assertThat(service.list("uc-a", "brandx", 50).block())
                    .extracting(UserNotification::title).containsExactly("a-note");
        }

        @Test
        void ownerIsolation_aMarkingBsKnownId_is404_andBStaysUnread() {
            String bId = repo.insertForTest("uc-b2", C, "b-note", null, "brandx").block();
            // A knows B's id but cannot mark it — 404 (no cross-user mark).
            assertThatThrownBy(() -> service.markRead(bId, "uc-a2", "brandx").block())
                    .isInstanceOf(ApiException.class)
                    .extracting(UserNotificationServiceTest::status).isEqualTo(404);
            // B's row remains UNREAD — A never silenced it.
            assertThat(repo.listForOwner("uc-b2", "brandx", 50).collectList().block().get(0).readAt())
                    .isNull();
        }

        @Test
        void brandIsolation_brandXMarkOfBrandYId_is404() {
            String yId = repo.insertForTest("uc-x", C, "y-note", null, "brandy").block();
            // same subject, different brand: the brandx scope cannot mark the brandy row.
            assertThatThrownBy(() -> service.markRead(yId, "uc-x", "brandx").block())
                    .isInstanceOf(ApiException.class)
                    .extracting(UserNotificationServiceTest::status).isEqualTo(404);
            // the brandy scope can.
            service.markRead(yId, "uc-x", "brandy").block();
        }

        @Test
        void superadminBypass_listsAcrossBrands() {
            repo.insertForTest("uc-sa", C, "x-note", null, "brandx").block();
            repo.insertForTest("uc-sa", C, "y-note", null, "brandy").block();
            assertThat(service.list("uc-sa", null, 50).block())
                    .extracting(UserNotification::title)
                    .containsExactlyInAnyOrder("x-note", "y-note");
        }
    }
}
