package net.hugmesh.userbff.web;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import net.hugmesh.userbff.profile.UsernameSkeleton;

/**
 * Validates {@link SafeDisplayName}: a display name is rejected when it carries a
 * zero-width / bidi-control / format code point, or is CONFUSABLE with a reserved
 * platform label. Reuses the SAME {@link UsernameSkeleton} engine as the
 * service-layer guard so the API and service checks can never drift.
 *
 * <p>A {@code null}/blank display name is VALID here (the field is optional; the
 * {@code @Size} constraint owns length). Only a present value is charset/confusable-
 * checked.
 */
public class SafeDisplayNameValidator implements ConstraintValidator<SafeDisplayName, String> {

    @Override
    public boolean isValid(String value, ConstraintValidatorContext context) {
        if (value == null || value.isBlank()) {
            return true;
        }
        if (UsernameSkeleton.hasForbiddenInvisible(value)) {
            return false;
        }
        return !UsernameSkeleton.isReservedConfusable(value);
    }
}
