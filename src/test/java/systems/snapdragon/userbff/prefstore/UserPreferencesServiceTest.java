package systems.snapdragon.userbff.prefstore;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import reactor.core.publisher.Flux;
import systems.snapdragon.userbff.media.MediaPoisoningProperties;
import systems.snapdragon.userbff.support.TestDatabaseConfig;
import systems.snapdragon.commons.web.ApiException;

import java.time.Duration;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * SERVICE-layer behaviour for {@link UserPreferencesService} over the real repository
 * slice — proves the defaults-merge resolution, the key/value validation, owner-AND-
 * domain isolation, and concurrent-upsert convergence. Delineated per the test
 * standard:
 *
 * <ul>
 *   <li><b>USER-SITUATIONAL</b> — a single user: an unset user inherits the server
 *       {@code MediaPoisoningProperties.defaultMode} for {@code media.poison.default};
 *       once set, the durable choice wins; an unknown key or a bad cloak-mode value is
 *       a clean 400; a blank owner is rejected.</li>
 *   <li><b>CROSS-USER</b> — owner A's get/put never sees or mutates owner B's durable
 *       value; a brand-X put cannot change a brand-Y value at the same owner+key;
 *       SUPERADMIN (null domain) resolves across brands.</li>
 *   <li><b>CONCURRENT</b> — concurrent puts of the same key by one owner converge to a
 *       single durable value (last-writer-wins, no duplicate, no lost-update crash).</li>
 * </ul>
 *
 * <p>NOTE: ONE shared H2 store across the class methods — each method uses a UNIQUE
 * owner id. The server default is pinned to {@code nightshade} in this test config so
 * the "inherits server default" assertion is unambiguous (distinct from the prod
 * {@code glaze} default).
 */
@DataR2dbcTest(properties = "app.media.poisoning.default-mode=nightshade")
@Import({TestDatabaseConfig.class, UserPreferencesStoreRepository.class,
        UserPreferencesServiceTest.Cfg.class})
class UserPreferencesServiceTest {

    @TestConfiguration(proxyBeanMethods = false)
    static class Cfg {
        /** Bind the server media-poisoning policy from the environment (the test sets
         *  the distinct {@code nightshade} default-mode) so the assertion proves the
         *  service mirrors the ACTUAL bound MediaPoisoningProperties, not a hand-poked
         *  field. */
        @Bean MediaPoisoningProperties mediaPoisoningProperties(
                org.springframework.core.env.Environment env) {
            MediaPoisoningProperties p = new MediaPoisoningProperties();
            p.setEnabled(true);
            p.setDefaultMode(env.getProperty("app.media.poisoning.default-mode", "glaze"));
            return p;
        }
        @Bean UserPreferencesService userPreferencesService(UserPreferencesStoreRepository repo,
                                                            MediaPoisoningProperties props) {
            return new UserPreferencesService(repo, props);
        }
    }

    @Autowired UserPreferencesService service;

    private static final String K = UserPreferencesService.MEDIA_POISON_DEFAULT;

    // ── USER-SITUATIONAL ──────────────────────────────────────────────────────
    @Nested
    class UserSituational {
        @Test
        void unsetUser_inheritsServerDefaultMode() {
            Map<String, String> view = service.get("us-1", "brandx").block();
            assertThat(view).containsEntry(K, "nightshade");      // mirrors MediaPoisoningProperties
        }

        @Test
        void put_thenGet_durableChoiceWins() {
            Map<String, String> afterPut = service.put("us-2", K, "glaze", "brandx").block();
            assertThat(afterPut).containsEntry(K, "glaze");
            // a fresh resolve still reflects the durable override, not the server default.
            assertThat(service.get("us-2", "brandx").block()).containsEntry(K, "glaze");
        }

        @Test
        void put_normalisesCaseToCanonicalMode() {
            assertThat(service.put("us-3", K, "GLAZE", "brandx").block()).containsEntry(K, "glaze");
        }

        @Test
        void put_unknownKey_isBadRequest() {
            assertThatThrownBy(() -> service.put("us-4", "totally.unknown", "x", "brandx").block())
                    .isInstanceOf(ApiException.class)
                    .extracting(e -> ((ApiException) e).status().value()).isEqualTo(400);
        }

        @Test
        void put_invalidCloakMode_isBadRequest() {
            assertThatThrownBy(() -> service.put("us-5", K, "rainbow", "brandx").block())
                    .isInstanceOf(ApiException.class)
                    .extracting(e -> ((ApiException) e).status().value()).isEqualTo(400);
        }

        @Test
        void blankOwner_isUnauthorized() {
            assertThatThrownBy(() -> service.get("  ", "brandx").block())
                    .isInstanceOf(ApiException.class)
                    .extracting(e -> ((ApiException) e).status().value()).isEqualTo(401);
        }

        @Test
        void put_noneOptOut_isAllowedAndDurable() {
            assertThat(service.put("us-6", K, "none", "brandx").block()).containsEntry(K, "none");
        }
    }

    // ── CROSS-USER ────────────────────────────────────────────────────────────
    @Nested
    class CrossUser {
        @Test
        void ownerIsolation_putByADoesNotAffectB() {
            service.put("cu-a", K, "glaze", "brandx").block();
            // owner B never set it ⇒ still the server default, untouched by A's put.
            assertThat(service.get("cu-b", "brandx").block()).containsEntry(K, "nightshade");
        }

        @Test
        void brandIsolation_putInBrandXDoesNotChangeBrandY() {
            service.put("cu-x", K, "glaze", "brandx").block();
            service.put("cu-x", K, "light", "brandy").block();
            assertThat(service.get("cu-x", "brandx").block()).containsEntry(K, "glaze");
            assertThat(service.get("cu-x", "brandy").block()).containsEntry(K, "light");
        }

        @Test
        void superadminBypass_resolvesAcrossBrands() {
            service.put("cu-sa", K, "glaze", "brandx").block();
            // null domain = SUPERADMIN bypass: the brandx durable value is visible.
            assertThat(service.get("cu-sa", null).block()).containsEntry(K, "glaze");
        }
    }

    // ── CONCURRENT ────────────────────────────────────────────────────────────
    @Nested
    class Concurrent {
        @Test
        void concurrentPutsSameKey_convergeToSingleDurableValue() {
            Flux.range(0, 30)
                    .flatMap(i -> service.put("conc-1", K, i % 2 == 0 ? "glaze" : "light", "brandx"))
                    .blockLast(Duration.ofSeconds(30));

            Map<String, String> view = service.get("conc-1", "brandx").block();
            // exactly one durable value survives (last-writer-wins); no duplicate/crash.
            assertThat(view.get(K)).isIn("glaze", "light");
        }
    }

    // ── APPEARANCE (mastodon-ui PreferencesService) ─────────────────────────────
    @Nested
    class Appearance {
        @Test
        void unsetUser_appearanceKeyIsAbsent_noServerOpinion() {
            // unlike media.poison.default, appearance keys have NO server default —
            // absence is itself the honest signal that the user hasn't customised it.
            Map<String, String> view = service.get("ap-1", "brandx").block();
            assertThat(view).doesNotContainKey(UserPreferencesService.APPEARANCE_THEME);
        }

        @Test
        void put_thenGet_appearanceChoiceIsDurable() {
            Map<String, String> after = service.put(
                    "ap-2", UserPreferencesService.APPEARANCE_THEME, "pastel-sky", "brandx").block();
            assertThat(after).containsEntry(UserPreferencesService.APPEARANCE_THEME, "pastel-sky");
            assertThat(service.get("ap-2", "brandx").block())
                    .containsEntry(UserPreferencesService.APPEARANCE_THEME, "pastel-sky");
        }

        @Test
        void put_booleanAppearanceKey_normalisesCase() {
            Map<String, String> after = service.put(
                    "ap-3", UserPreferencesService.APPEARANCE_HIGH_CONTRAST, "TRUE", "brandx").block();
            assertThat(after).containsEntry(UserPreferencesService.APPEARANCE_HIGH_CONTRAST, "true");
        }

        @Test
        void put_invalidAppearanceEnumValue_isBadRequest() {
            assertThatThrownBy(() -> service.put(
                    "ap-4", UserPreferencesService.APPEARANCE_LAYOUT, "triple-column", "brandx").block())
                    .isInstanceOf(ApiException.class)
                    .extracting(e -> ((ApiException) e).status().value()).isEqualTo(400);
        }

        @Test
        void put_invalidBooleanAppearanceValue_isBadRequest() {
            assertThatThrownBy(() -> service.put(
                    "ap-5", UserPreferencesService.APPEARANCE_REDUCED_MOTION, "maybe", "brandx").block())
                    .isInstanceOf(ApiException.class)
                    .extracting(e -> ((ApiException) e).status().value()).isEqualTo(400);
        }

        @Test
        void put_allAppearanceKeys_areAccepted() {
            Map<String, String> valid = Map.of(
                    UserPreferencesService.APPEARANCE_THEME, "mono",
                    UserPreferencesService.APPEARANCE_ACCENT, "peach",
                    UserPreferencesService.APPEARANCE_APPEARANCE, "light",
                    UserPreferencesService.APPEARANCE_LAYOUT, "multi",
                    UserPreferencesService.APPEARANCE_DENSITY, "compact",
                    UserPreferencesService.APPEARANCE_MEDIA_CORNERS, "square",
                    UserPreferencesService.APPEARANCE_FONT, "dyslexic",
                    UserPreferencesService.APPEARANCE_TEXT_SIZE, "xl",
                    UserPreferencesService.APPEARANCE_HIGH_CONTRAST, "true",
                    UserPreferencesService.APPEARANCE_REDUCED_MOTION, "false");
            Map<String, String> resolved = Map.of();
            for (var entry : valid.entrySet()) {
                resolved = service.put("ap-6", entry.getKey(), entry.getValue(), "brandx").block();
            }
            for (var entry : valid.entrySet()) {
                assertThat(resolved).containsEntry(entry.getKey(), entry.getValue());
            }
        }

        @Test
        void ownerIsolation_appearanceChoiceByADoesNotAffectB() {
            service.put("ap-a", UserPreferencesService.APPEARANCE_THEME, "mono", "brandx").block();
            Map<String, String> viewB = service.get("ap-b", "brandx").block();
            assertThat(viewB).doesNotContainKey(UserPreferencesService.APPEARANCE_THEME);
        }
    }
}
