package systems.snapdragon.userbff.web;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * API-layer (jakarta Bean Validation) half of the displayName impersonation guard
 * (GAP 2). A {@code displayName} carrying a zero-width / bidi-control / format code
 * point, or one that is CONFUSABLE with a reserved platform label, is rejected with
 * a clean 400 at the {@code @Valid @RequestBody} boundary — BEFORE the service runs
 * — as defence-in-depth alongside the same check in {@code ProfileService} (so the
 * guard holds even on a code path that bypasses the controller).
 *
 * @see SafeDisplayNameValidator
 */
@Documented
@Constraint(validatedBy = SafeDisplayNameValidator.class)
@Target({ElementType.FIELD, ElementType.PARAMETER, ElementType.RECORD_COMPONENT})
@Retention(RetentionPolicy.RUNTIME)
public @interface SafeDisplayName {

    String message() default
            "displayName must not contain invisible/bidirectional characters or impersonate a reserved name";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};
}
