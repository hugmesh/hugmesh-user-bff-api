package systems.snapdragon.userbff.web;

import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import systems.snapdragon.userbff.profile.UserProfile;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * API-LAYER (jakarta Bean Validation) test for the {@link SafeDisplayName}
 * constraint on {@code UserProfile.displayName} — the {@code @Valid @RequestBody}
 * boundary half of the GAP-2 displayName guard. Drives the real {@link Validator}
 * over {@link UserProfile} instances (the same validation Spring runs on the
 * controller's {@code @Valid} body), proving a zero-width / bidi / confusable-of-
 * reserved display name is a constraint violation BEFORE the service runs, while a
 * normal one is valid.
 */
class SafeDisplayNameValidatorTest {

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

    private static UserProfile withDisplayName(String displayName) {
        return new UserProfile("sub", null, null, null, displayName, "internal", false);
    }

    private boolean displayNameViolated(String displayName) {
        return validator.validate(withDisplayName(displayName)).stream()
                .anyMatch(v -> v.getPropertyPath().toString().equals("displayName"));
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "ad​min",   // ZERO WIDTH SPACE
            "Ali‍ce",   // ZERO WIDTH JOINER
            "test‮moc", // RIGHT-TO-LEFT OVERRIDE (bidi)
            "admin",     // exact reserved
            "4dmin",     // leet confusable
            "ad-min",    // separator-stripped confusable
            "аdmin",     // Cyrillic homograph of admin
    })
    void badDisplayNames_violateConstraint(String bad) {
        assertThat(displayNameViolated(bad))
                .as("'%s' should violate @SafeDisplayName", bad)
                .isTrue();
    }

    @ParameterizedTest
    @ValueSource(strings = {"Anna Müller", "Carol", "bob", "Zoé", "José"})
    void normalDisplayNames_pass(String ok) {
        assertThat(displayNameViolated(ok))
                .as("'%s' should be a valid display name", ok)
                .isFalse();
    }

    @Test
    void nullAndBlankDisplayName_areValid() {
        assertThat(displayNameViolated(null)).isFalse();
        assertThat(displayNameViolated("   ")).isFalse();
    }
}
