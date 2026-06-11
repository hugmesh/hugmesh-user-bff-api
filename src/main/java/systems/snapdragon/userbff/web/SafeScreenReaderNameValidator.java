package systems.snapdragon.userbff.web;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

/**
 * Validates {@link SafeScreenReaderName}: a screen-reader name is rejected when it is
 * NOT pure printable ASCII or carries a forbidden zero-width / bidi / format /
 * control code point. Reuses the SAME {@link ScreenReaderNames} engine as the
 * service-layer guard so the API and service checks can never drift.
 *
 * <p>A {@code null}/blank screen-reader name is VALID here (the field is optional; the
 * service derives a default from the display name or prompts for one). Only a present
 * value is charset-checked.
 */
public class SafeScreenReaderNameValidator
        implements ConstraintValidator<SafeScreenReaderName, String> {

    @Override
    public boolean isValid(String value, ConstraintValidatorContext context) {
        return ScreenReaderNames.isSafeScreenReaderName(value);
    }
}
