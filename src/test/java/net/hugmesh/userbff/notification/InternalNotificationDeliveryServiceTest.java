package net.hugmesh.userbff.notification;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.r2dbc.core.DatabaseClient;
import net.hugmesh.userbff.notification.InternalNotificationDeliveryService.DeliveryResult;
import net.hugmesh.userbff.support.TestDatabaseConfig;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integration test for the internal deliver path ({@link InternalNotificationDeliveryService}
 * over the real {@link UserNotificationRepository} + {@link NotificationPreferenceRepository}
 * against the Liquibase-applied H2 schema). Proves the deliver SEMANTICS the controller
 * gate sits above. Delineated per the test standard:
 *
 * <ul>
 *   <li><b>USER-SITUATIONAL</b> — a default-prefs target gets the row; the row lands for
 *       the EXACT (domain, userSubject) from the body; no actor identity is introduced
 *       (title/body verbatim from the request).</li>
 *   <li><b>CONCURRENT/RETRY (idempotency)</b> — delivering the same (sourceTable,
 *       sourceId) twice writes EXACTLY ONE row; the retry reports deduped=true.</li>
 *   <li><b>PREFS</b> — a suppressed non-restriction category → delivered=false, NO row;
 *       the FORCED-ON account-restriction is delivered even when the pref says
 *       disabled.</li>
 * </ul>
 *
 * <p>NOTE: ONE shared H2 store across the class methods — each method uses a UNIQUE
 * owner id so the methods don't interfere.
 */
@DataR2dbcTest
@Import({TestDatabaseConfig.class, UserNotificationRepository.class,
        NotificationPreferenceRepository.class, SseNotificationBus.class, InternalNotificationDeliveryService.class})
class InternalNotificationDeliveryServiceTest {

    @Autowired InternalNotificationDeliveryService service;
    @Autowired UserNotificationRepository notifications;
    @Autowired NotificationPreferenceRepository preferences;
    @Autowired DatabaseClient db;

    /** Count rows directly for the EXACT (domain, owner) — the authoritative isolation
     *  assertion (the repo's own list is owner+domain scoped too, but a raw count proves
     *  no row leaked under a DIFFERENT domain/owner). */
    private long countRows(String domain, String owner) {
        return db.sql("SELECT count(*) AS c FROM user_notifications "
                        + "WHERE domain = :d AND user_subject = :u")
                .bind("d", domain).bind("u", owner)
                .map((row, m) -> row.get("c", Long.class))
                .one().block();
    }

    private long countAllForOwner(String owner) {
        return db.sql("SELECT count(*) AS c FROM user_notifications WHERE user_subject = :u")
                .bind("u", owner)
                .map((row, m) -> row.get("c", Long.class))
                .one().block();
    }

    // ── USER-SITUATIONAL ──────────────────────────────────────────────────────
    @Nested
    class UserSituational {

        @Test
        void deliver_defaultPrefs_writesRowForExactTarget() {
            DeliveryResult r = service.deliver("brandx", "u-deliver", NotificationCategory.ROLE_CHANGE,
                    "Role changed", "You are now MOD.", "role_grant", "rg-1").block();

            assertThat(r.delivered()).isTrue();
            assertThat(r.deduped()).isFalse();

            // the row lands for the EXACT (domain, userSubject) from the body...
            List<UserNotification> rows =
                    notifications.listForOwner("u-deliver", "brandx", 50).collectList().block();
            assertThat(rows).hasSize(1);
            UserNotification n = rows.get(0);
            assertThat(n.category()).isEqualTo(NotificationCategory.ROLE_CHANGE);
            // ...with the title/body VERBATIM from the request — no actor identity
            // synthesised, no "from <admin>" injected.
            assertThat(n.title()).isEqualTo("Role changed");
            assertThat(n.body()).isEqualTo("You are now MOD.");

            // and NOTHING leaked to a different brand or owner.
            assertThat(countRows("brandx", "u-deliver")).isEqualTo(1L);
            assertThat(countRows("brandy", "u-deliver")).isEqualTo(0L);
            assertThat(countAllForOwner("someone-else")).isEqualTo(0L);
        }

        @Test
        void deliver_titleOnly_nullBodyIsAllowed() {
            DeliveryResult r = service.deliver("brandx", "u-titleonly", NotificationCategory.INFRA_IMPACTING,
                    "Maintenance tonight", null, "infra_event", "ie-1").block();
            assertThat(r.delivered()).isTrue();

            UserNotification n =
                    notifications.listForOwner("u-titleonly", "brandx", 50).collectList().block().get(0);
            assertThat(n.title()).isEqualTo("Maintenance tonight");
            assertThat(n.body()).isNull();
        }
    }

    // ── CONCURRENT / RETRY (idempotency) ──────────────────────────────────────
    @Nested
    class Idempotency {

        @Test
        void deliverTwiceSameSource_writesExactlyOneRow_secondIsDeduped() {
            DeliveryResult first = service.deliver("brandx", "u-idem", NotificationCategory.ROLE_CHANGE,
                    "Role changed", "body", "role_grant", "same-source-99").block();
            DeliveryResult second = service.deliver("brandx", "u-idem", NotificationCategory.ROLE_CHANGE,
                    "Role changed", "body", "role_grant", "same-source-99").block();

            assertThat(first.delivered()).isTrue();
            assertThat(first.deduped()).isFalse();   // first inserts
            assertThat(second.delivered()).isTrue();
            assertThat(second.deduped()).isTrue();   // retry is a dedupe, not a second row

            // EXACTLY ONE row despite two calls.
            assertThat(countRows("brandx", "u-idem")).isEqualTo(1L);
        }

        @Test
        void differentSourceIds_writeDistinctRows() {
            service.deliver("brandx", "u-distinct", NotificationCategory.ROLE_CHANGE,
                    "t", "b", "role_grant", "src-A").block();
            service.deliver("brandx", "u-distinct", NotificationCategory.ROLE_CHANGE,
                    "t", "b", "role_grant", "src-B").block();
            assertThat(countRows("brandx", "u-distinct")).isEqualTo(2L);
        }

        @Test
        void deterministicId_matchesStableHash() {
            service.deliver("brandx", "u-hash", NotificationCategory.ROLE_CHANGE,
                    "t", "b", "role_grant", "evt-7").block();
            String expectedId = StableNotificationId.forInApp("role_grant", "evt-7");
            assertThat(notifications.existsById(expectedId).block()).isTrue();
        }
    }

    // ── PREFS (suppression + forced-on) ───────────────────────────────────────
    @Nested
    class Prefs {

        @Test
        void suppressedCategory_isNotDelivered_noRow() {
            // the target explicitly disabled the (silenceable) role-change category.
            preferences.upsert("u-suppress", NotificationCategory.ROLE_CHANGE, false, "brandx").block();

            DeliveryResult r = service.deliver("brandx", "u-suppress", NotificationCategory.ROLE_CHANGE,
                    "Role changed", "body", "role_grant", "rg-supp").block();

            assertThat(r.delivered()).isFalse();
            assertThat(r.reason()).isEqualTo("suppressed");
            assertThat(countRows("brandx", "u-suppress")).isEqualTo(0L);   // NO write
        }

        @Test
        void accountRestriction_isForcedOn_deliveredEvenWhenPrefDisabled() {
            // even if a (stale) row somehow said disabled, account-restriction is
            // un-silenceable — the deliver path ignores the pref for this category.
            // (The prefs upsert itself coerces it on; we write the row directly to
            // simulate a hostile/stale disabled row and prove deliver still fires.)
            db.sql("INSERT INTO notification_preference "
                            + "(domain, user_subject, category, enabled, updated_at) "
                            + "VALUES ('brandx', 'u-forced', 'role-change', FALSE, now())")
                    .fetch().rowsUpdated().block();
            // sanity: a silenceable category IS suppressed for this owner.
            DeliveryResult suppressed = service.deliver("brandx", "u-forced",
                    NotificationCategory.ROLE_CHANGE, "t", "b", "role_grant", "rg-x").block();
            assertThat(suppressed.delivered()).isFalse();

            // account-restriction is delivered regardless of any stored preference.
            DeliveryResult forced = service.deliver("brandx", "u-forced",
                    NotificationCategory.ACCOUNT_RESTRICTION,
                    "Account restricted", "Your account was suspended.",
                    "access_suspension", "as-1").block();

            assertThat(forced.delivered()).isTrue();
            assertThat(forced.deduped()).isFalse();
            List<UserNotification> rows =
                    notifications.listForOwner("u-forced", "brandx", 50).collectList().block();
            assertThat(rows).extracting(UserNotification::category)
                    .containsExactly(NotificationCategory.ACCOUNT_RESTRICTION);
        }

        @Test
        void enabledCategory_isDelivered() {
            preferences.upsert("u-enabled", NotificationCategory.FEATURE_AVAILABILITY, true, "brandx").block();
            DeliveryResult r = service.deliver("brandx", "u-enabled",
                    NotificationCategory.FEATURE_AVAILABILITY, "New feature", "b", "feature_flag", "ff-1").block();
            assertThat(r.delivered()).isTrue();
            assertThat(countRows("brandx", "u-enabled")).isEqualTo(1L);
        }

        @Test
        void prefIsPerBrand_suppressInBrandXDoesNotSuppressBrandY() {
            preferences.upsert("u-perbrand", NotificationCategory.ROLE_CHANGE, false, "brandx").block();

            // brandx suppressed...
            assertThat(service.deliver("brandx", "u-perbrand", NotificationCategory.ROLE_CHANGE,
                    "t", "b", "role_grant", "pb-x").block().delivered()).isFalse();
            // ...brandy (no pref row) defaults ENABLED and delivers.
            assertThat(service.deliver("brandy", "u-perbrand", NotificationCategory.ROLE_CHANGE,
                    "t", "b", "role_grant", "pb-y").block().delivered()).isTrue();

            assertThat(countRows("brandx", "u-perbrand")).isEqualTo(0L);
            assertThat(countRows("brandy", "u-perbrand")).isEqualTo(1L);
        }
    }

    // ── VALIDATION (fail-closed) ──────────────────────────────────────────────
    @Nested
    class Validation {

        @Test
        void unknownCategory_isRejected_noRow() {
            assertThat(
                    catchThrowable(() -> service.deliver("brandx", "u-badcat", "not-a-real-category",
                            "t", "b", "role_grant", "bc-1").block()))
                    .isInstanceOf(net.hugmesh.commons.web.ApiException.class);
            assertThat(countRows("brandx", "u-badcat")).isEqualTo(0L);
        }

        @Test
        void blankUserSubject_isRejected() {
            assertThat(
                    catchThrowable(() -> service.deliver("brandx", "  ", NotificationCategory.ROLE_CHANGE,
                            "t", "b", "role_grant", "bu-1").block()))
                    .isInstanceOf(net.hugmesh.commons.web.ApiException.class);
        }
    }

    private static Throwable catchThrowable(Runnable r) {
        try {
            r.run();
            return null;
        } catch (Throwable t) {
            return t;
        }
    }
}
