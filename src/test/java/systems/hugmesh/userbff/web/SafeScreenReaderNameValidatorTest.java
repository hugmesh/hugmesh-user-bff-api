package systems.hugmesh.userbff.web;

import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import systems.hugmesh.userbff.profile.UserProfile;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * API-LAYER (jakarta Bean Validation) test for the {@link SafeScreenReaderName}
 * constraint on {@code UserProfile.screenReaderName} — the {@code @Valid @RequestBody}
 * boundary half of the a11y screen-reader-name guard. Drives the real {@link Validator}
 * over {@link UserProfile} instances (the same validation Spring runs on the
 * controller's {@code @Valid} body), proving a NON-ASCII / zero-width / control
 * screen-reader name is a constraint violation BEFORE the service runs, while an ASCII
 * one (and null/blank) is valid.
 */
class SafeScreenReaderNameValidatorTest {

    private static ValidatorFactory factory;
    private static Validator validator;

    @BeforeAll
    static void setUp() {
        factory = Validation.buildDefaultValidatorFactory();
        validator = factory.getValidator();
    }

    @AfterAll
    static void tearDown() {
        factory.close();
    }

    private static UserProfile withScreenReaderName(String srn) {
        // ASCII display name so ONLY the screenReaderName field is under test.
        return new UserProfile("sub", null, null, null, "Alice", "internal", false, null, srn);
    }

    private boolean screenReaderNameViolated(String srn) {
        return validator.validate(withScreenReaderName(srn)).stream()
                .anyMatch(v -> v.getPropertyPath().toString().equals("screenReaderName"));
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "José",        // accented Latin — non-ASCII
            "Анна",        // Cyrillic
            "山田",         // CJK
            "emoji😀",      // emoji
            "ad​min",      // ZERO WIDTH SPACE
            "test‮moc",    // RIGHT-TO-LEFT OVERRIDE (bidi)
    })
    void nonAsciiScreenReaderNames_violateConstraint(String bad) {
        assertThat(screenReaderNameViolated(bad))
                .as("'%s' should violate @SafeScreenReaderName", bad)
                .isTrue();
    }

    @ParameterizedTest
    @ValueSource(strings = {"Alice", "Jose", "Yamada Taro", "bob-99", "A B C", "a~b!c"})
    void asciiScreenReaderNames_pass(String ok) {
        assertThat(screenReaderNameViolated(ok))
                .as("'%s' should be a valid screen-reader name", ok)
                .isFalse();
    }

    @Test
    void nullAndBlankScreenReaderName_areValid() {
        assertThat(screenReaderNameViolated(null)).isFalse();
        assertThat(screenReaderNameViolated("   ")).isFalse();
    }
}
