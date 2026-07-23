package systems.hugmesh.userbff.web;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit test for the SCREEN-READER NAME charset + default/prompt logic
 * ({@link ScreenReaderNames}) — the single home shared by the API validator, the
 * service guard, and the registration/profile-save default/prompt flow. Asserts:
 * <ul>
 *   <li>ASCII detection — printable ASCII passes, accented/script/emoji/control fails;</li>
 *   <li>safe-screen-reader-name — ASCII + invisible-free passes, non-ASCII /
 *       zero-width fails (null/blank is acceptable);</li>
 *   <li>defaultFor — an ASCII display name defaults to itself; a non-ASCII one has no
 *       safe default (null);</li>
 *   <li>requiresScreenReaderName — true ONLY when the display name is non-ASCII and no
 *       usable ASCII screen-reader name was supplied.</li>
 * </ul>
 */
class ScreenReaderNamesTest {

    @ParameterizedTest
    @ValueSource(strings = {"Alice", "bob", "Al-Bob_99", "name with spaces", "a~b!c", "ASCII Only 123"})
    void asciiNames_areAscii(String s) {
        assertThat(ScreenReaderNames.isAscii(s)).as("'%s' is ASCII", s).isTrue();
        assertThat(ScreenReaderNames.isSafeScreenReaderName(s)).isTrue();
    }

    @ParameterizedTest
    @ValueSource(strings = {"José", "Zoé", "Анна", "山田", "Müller", "name​zero", "tab\there", "emoji😀"})
    void nonAsciiOrControl_areNotAscii(String s) {
        assertThat(ScreenReaderNames.isAscii(s)).as("'%s' is not ASCII", s).isFalse();
        assertThat(ScreenReaderNames.isSafeScreenReaderName(s))
                .as("'%s' is not a safe screen-reader name", s).isFalse();
    }

    @Test
    void nullAndBlank_areAsciiAndSafe() {
        assertThat(ScreenReaderNames.isAscii(null)).isTrue();
        assertThat(ScreenReaderNames.isAscii("")).isTrue();
        assertThat(ScreenReaderNames.isSafeScreenReaderName(null)).isTrue();
        assertThat(ScreenReaderNames.isSafeScreenReaderName("   ")).isTrue();
    }

    @Test
    void zeroWidth_isUnsafeEvenThoughOutsidePrintableAscii() {
        // A zero-width space is > U+007E so the ASCII check already rejects it; the
        // invisible check is the belt-and-braces second wall.
        assertThat(ScreenReaderNames.isSafeScreenReaderName("ad​min")).isFalse();
    }

    @Test
    void defaultFor_asciiDisplayName_defaultsToItself() {
        assertThat(ScreenReaderNames.defaultFor("Alice")).isEqualTo("Alice");
        assertThat(ScreenReaderNames.defaultFor("bob 99")).isEqualTo("bob 99");
    }

    @Test
    void defaultFor_nonAsciiDisplayName_hasNoSafeDefault() {
        assertThat(ScreenReaderNames.defaultFor("José")).isNull();
        assertThat(ScreenReaderNames.defaultFor("山田太郎")).isNull();
    }

    @Test
    void defaultFor_nullOrBlankDisplayName_isNull() {
        assertThat(ScreenReaderNames.defaultFor(null)).isNull();
        assertThat(ScreenReaderNames.defaultFor("  ")).isNull();
    }

    @Test
    void requiresScreenReaderName_asciiDisplayName_neverPrompts() {
        // ASCII display name defaults — never requires an explicit screen-reader name.
        assertThat(ScreenReaderNames.requiresScreenReaderName("Alice", null)).isFalse();
        assertThat(ScreenReaderNames.requiresScreenReaderName("Alice", "")).isFalse();
    }

    @Test
    void requiresScreenReaderName_nonAsciiDisplayName_withoutScreenReaderName_prompts() {
        assertThat(ScreenReaderNames.requiresScreenReaderName("José", null)).isTrue();
        assertThat(ScreenReaderNames.requiresScreenReaderName("José", "  ")).isTrue();
        // an ASCII screen-reader name IS usable → no prompt
        assertThat(ScreenReaderNames.requiresScreenReaderName("José", "Jose")).isFalse();
        // a non-ASCII "screen-reader name" is itself NOT usable → still prompts
        assertThat(ScreenReaderNames.requiresScreenReaderName("José", "José")).isTrue();
    }

    @Test
    void requiresScreenReaderName_nonAsciiDisplayName_withAsciiScreenReaderName_doesNotPrompt() {
        assertThat(ScreenReaderNames.requiresScreenReaderName("José", "Jose")).isFalse();
        assertThat(ScreenReaderNames.requiresScreenReaderName("山田太郎", "Yamada Taro")).isFalse();
    }

    @Test
    void requiresScreenReaderName_nullOrBlankDisplayName_doesNotPrompt() {
        assertThat(ScreenReaderNames.requiresScreenReaderName(null, null)).isFalse();
        assertThat(ScreenReaderNames.requiresScreenReaderName("  ", null)).isFalse();
    }
}
