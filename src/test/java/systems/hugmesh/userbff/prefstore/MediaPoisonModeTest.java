package systems.hugmesh.userbff.prefstore;

import org.junit.jupiter.api.Test;
import systems.hugmesh.userbff.media.CloakMode;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The user-facing {@link MediaPoisonMode} contract vocabulary: exact wire tokens, the
 * closed accept/reject guard, and the 1:1 engine ({@link CloakMode}) mapping in both
 * directions — the seam that keeps the {@code media.poison.default} preference contract
 * ({@code off|low|medium|high}) aligned with the cloak pipeline
 * ({@code none|light|glaze|nightshade}) without either vocabulary leaking into the other.
 */
class MediaPoisonModeTest {

    @Test
    void wireTokens_areExactlyTheContractVocabulary() {
        assertThat(MediaPoisonMode.OFF.value()).isEqualTo("off");
        assertThat(MediaPoisonMode.LOW.value()).isEqualTo("low");
        assertThat(MediaPoisonMode.MEDIUM.value()).isEqualTo("medium");
        assertThat(MediaPoisonMode.HIGH.value()).isEqualTo("high");
        assertThat(MediaPoisonMode.VOCABULARY).isEqualTo("off|low|medium|high");
    }

    @Test
    void fromWire_acceptsExactlyTheFourTokens_rejectsEverythingElse() {
        assertThat(MediaPoisonMode.fromWire("off")).isEqualTo(MediaPoisonMode.OFF);
        assertThat(MediaPoisonMode.fromWire("low")).isEqualTo(MediaPoisonMode.LOW);
        assertThat(MediaPoisonMode.fromWire("medium")).isEqualTo(MediaPoisonMode.MEDIUM);
        assertThat(MediaPoisonMode.fromWire("high")).isEqualTo(MediaPoisonMode.HIGH);
        // engine tokens are NOT wire tokens (strict user-facing contract).
        assertThat(MediaPoisonMode.fromWire("glaze")).isNull();
        assertThat(MediaPoisonMode.fromWire("nightshade")).isNull();
        assertThat(MediaPoisonMode.fromWire("light")).isNull();
        assertThat(MediaPoisonMode.fromWire("none")).isNull();
        assertThat(MediaPoisonMode.fromWire("OFF")).isNull();   // canonical lowercase only
        assertThat(MediaPoisonMode.fromWire("")).isNull();
        assertThat(MediaPoisonMode.fromWire(null)).isNull();
        assertThat(MediaPoisonMode.isValid("medium")).isTrue();
        assertThat(MediaPoisonMode.isValid("rainbow")).isFalse();
    }

    @Test
    void engineMapping_isOneToOne_bothDirections() {
        assertThat(MediaPoisonMode.OFF.engineMode()).isEqualTo(CloakMode.NONE);
        assertThat(MediaPoisonMode.LOW.engineMode()).isEqualTo(CloakMode.LIGHT);
        assertThat(MediaPoisonMode.MEDIUM.engineMode()).isEqualTo(CloakMode.GLAZE);
        assertThat(MediaPoisonMode.HIGH.engineMode()).isEqualTo(CloakMode.NIGHTSHADE);

        assertThat(MediaPoisonMode.fromEngineToken("none")).isEqualTo(MediaPoisonMode.OFF);
        assertThat(MediaPoisonMode.fromEngineToken("light")).isEqualTo(MediaPoisonMode.LOW);
        assertThat(MediaPoisonMode.fromEngineToken("glaze")).isEqualTo(MediaPoisonMode.MEDIUM);
        assertThat(MediaPoisonMode.fromEngineToken("nightshade")).isEqualTo(MediaPoisonMode.HIGH);
        assertThat(MediaPoisonMode.fromEngineToken("off")).isNull();   // not an engine token
        assertThat(MediaPoisonMode.fromEngineToken(null)).isNull();

        // EVERY engine mode has a user-facing token (no unmapped cloak mode can appear).
        for (CloakMode engine : CloakMode.values()) {
            assertThat(MediaPoisonMode.fromEngineToken(engine.value()))
                    .as("engine mode %s must map to a user-facing mode", engine)
                    .isNotNull();
        }
    }

    @Test
    void canonicalPoisonToken_handlesContractEngineAndGarbage() {
        assertThat(UserPreferencesService.canonicalPoisonToken("high")).isEqualTo("high");
        assertThat(UserPreferencesService.canonicalPoisonToken(" MEDIUM ")).isEqualTo("medium");
        assertThat(UserPreferencesService.canonicalPoisonToken("glaze")).isEqualTo("medium");
        assertThat(UserPreferencesService.canonicalPoisonToken("nightshade")).isEqualTo("high");
        assertThat(UserPreferencesService.canonicalPoisonToken("light")).isEqualTo("low");
        assertThat(UserPreferencesService.canonicalPoisonToken("none")).isEqualTo("off");
        assertThat(UserPreferencesService.canonicalPoisonToken("garbage")).isEqualTo("medium");
        assertThat(UserPreferencesService.canonicalPoisonToken(null)).isEqualTo("medium");
    }
}
