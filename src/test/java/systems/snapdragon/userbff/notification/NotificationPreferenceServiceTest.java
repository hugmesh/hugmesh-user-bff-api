package systems.snapdragon.userbff.notification;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.data.r2dbc.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import systems.snapdragon.userbff.support.TestDatabaseConfig;
import systems.snapdragon.userbff.web.ApiException;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * SERVICE-layer behaviour for {@link NotificationPreferenceService} over the real
 * repository slice — proves the defaults-merge resolution, the category validation,
 * owner-AND-domain isolation, and (the headline) the FORCED-ON account-restriction
 * coercion. Delineated per the test standard:
 *
 * <ul>
 *   <li><b>USER-SITUATIONAL</b> — an unset user sees every category ENABLED by default;
 *       once set, the durable choice wins; an unknown category is a clean 400; a blank
 *       owner is rejected 401; account-restriction enabled=false is COERCED to enabled
 *       (never silenced) on both put + the resolved view.</li>
 *   <li><b>CROSS-USER</b> — owner A's put never sees or mutates owner B's value; a
 *       brand-X put cannot change a brand-Y value at the same owner+category; SUPERADMIN
 *       (null domain) resolves across brands.</li>
 * </ul>
 *
 * <p>NOTE: ONE shared H2 store across the class methods — each method uses a UNIQUE
 * owner id.
 */
@DataR2dbcTest
@Import({TestDatabaseConfig.class, NotificationPreferenceRepository.class,
        NotificationPreferenceServiceTest.Cfg.class})
class NotificationPreferenceServiceTest {

    @org.springframework.boot.test.context.TestConfiguration(proxyBeanMethods = false)
    static class Cfg {
        @org.springframework.context.annotation.Bean
        NotificationPreferenceService notificationPreferenceService(NotificationPreferenceRepository repo) {
            return new NotificationPreferenceService(repo);
        }
    }

    @Autowired NotificationPreferenceService service;

    private static final String AR = NotificationCategory.ACCOUNT_RESTRICTION;
    private static final String RC = NotificationCategory.ROLE_CHANGE;

    // ── USER-SITUATIONAL ──────────────────────────────────────────────────────
    @Nested
    class UserSituational {
        @Test
        void unsetUser_everyCategoryEnabledByDefault() {
            Map<String, Boolean> view = service.get("ns-1", "brandx").block();
            assertThat(view)
                    .containsEntry(AR, true)
                    .containsEntry(RC, true)
                    .containsEntry(NotificationCategory.INFRA_IMPACTING, true)
                    .containsEntry(NotificationCategory.FEATURE_AVAILABILITY, true)
                    .hasSize(NotificationCategory.ALL.size());
        }

        @Test
        void put_disableSilenceable_thenGet_durableChoiceWins() {
            Map<String, Boolean> afterPut = service.put("ns-2", RC, false, "brandx").block();
            assertThat(afterPut).containsEntry(RC, false);
            // a fresh resolve still reflects the durable override, not the default.
            assertThat(service.get("ns-2", "brandx").block()).containsEntry(RC, false);
            // unrelated categories remain at their default.
            assertThat(service.get("ns-2", "brandx").block())
                    .containsEntry(NotificationCategory.INFRA_IMPACTING, true);
        }

        @Test
        void put_reEnableSilenceable_isDurable() {
            service.put("ns-3", RC, false, "brandx").block();
            assertThat(service.put("ns-3", RC, true, "brandx").block()).containsEntry(RC, true);
        }

        @Test
        void put_unknownCategory_isBadRequest() {
            assertThatThrownBy(() -> service.put("ns-4", "totally-unknown", false, "brandx").block())
                    .isInstanceOf(ApiException.class)
                    .extracting(e -> ((ApiException) e).status().value()).isEqualTo(400);
        }

        @Test
        void blankOwner_isUnauthorized() {
            assertThatThrownBy(() -> service.get("  ", "brandx").block())
                    .isInstanceOf(ApiException.class)
                    .extracting(e -> ((ApiException) e).status().value()).isEqualTo(401);
        }

        // ── FORCED-ON / un-silenceable account-restriction ────────────────────
        @Test
        void accountRestriction_putDisable_isCoercedToEnabled_neverSilenced() {
            // attempt to silence account-restriction: the resolved view shows it ENABLED.
            Map<String, Boolean> view = service.put("ns-ar", AR, false, "brandx").block();
            assertThat(view).containsEntry(AR, true);
            // and a fresh resolve still shows it enabled (the durable row was coerced).
            assertThat(service.get("ns-ar", "brandx").block()).containsEntry(AR, true);
        }

        @Test
        void accountRestriction_alwaysEnabledInResolvedView_evenAfterSilenceAttempt() {
            // even if the silenceable categories are turned off, account-restriction stays on.
            service.put("ns-ar2", RC, false, "brandx").block();
            service.put("ns-ar2", AR, false, "brandx").block();
            Map<String, Boolean> view = service.get("ns-ar2", "brandx").block();
            assertThat(view).containsEntry(AR, true).containsEntry(RC, false);
        }
    }

    // ── CROSS-USER ────────────────────────────────────────────────────────────
    @Nested
    class CrossUser {
        @Test
        void ownerIsolation_putByADoesNotAffectB() {
            service.put("nc-a", RC, false, "brandx").block();
            // owner B never set it ⇒ still the default (enabled), untouched by A's put.
            assertThat(service.get("nc-b", "brandx").block()).containsEntry(RC, true);
        }

        @Test
        void brandIsolation_putInBrandXDoesNotChangeBrandY() {
            service.put("nc-x", RC, false, "brandx").block();
            // brandy never set it ⇒ default enabled.
            assertThat(service.get("nc-x", "brandx").block()).containsEntry(RC, false);
            assertThat(service.get("nc-x", "brandy").block()).containsEntry(RC, true);
        }

        @Test
        void superadminBypass_resolvesAcrossBrands() {
            service.put("nc-sa", RC, false, "brandx").block();
            // null domain = SUPERADMIN bypass: the brandx durable value is visible.
            assertThat(service.get("nc-sa", null).block()).containsEntry(RC, false);
        }
    }
}
