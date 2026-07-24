package systems.hugmesh.userbff.web;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * API-layer (jakarta Bean Validation) guard for {@code UserProfile.screenReaderName}
 * — the a11y aria-label / spoken name a screen reader announces for the user.
 *
 * <p>A screen-reader name must be ASCII-ONLY and carry NO special / zero-width /
 * bidi-control / format / control characters: it is the value a screen reader reads
 * aloud, so it must be a clean, pronounceable string a homograph cannot be smuggled
 * into. (This is STRICTER than {@link SafeDisplayName}, which permits accented Latin
 * and other scripts in the human-visible display name — the screen-reader name is the
 * ASCII-safe spoken counterpart of exactly such a non-ASCII display name.)
 *
 * <p>A {@code null}/blank screen-reader name is VALID here (the field is optional; the
 * service derives/defaults it from the display name or prompts for one). Only a
 * present value is charset-checked. Defence-in-depth: the SAME ASCII rule is re-checked
 * in {@code ProfileService} so the guard holds even on a path that bypasses the
 * controller.
 *
 * @see SafeScreenReaderNameValidator
 */
@Documented
@Constraint(validatedBy = SafeScreenReaderNameValidator.class)
@Target({ElementType.FIELD, ElementType.PARAMETER, ElementType.RECORD_COMPONENT})
@Retention(RetentionPolicy.RUNTIME)
public @interface SafeScreenReaderName {

    String message() default
            "screenReaderName must be ASCII-only with no special, invisible, or control characters";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};
}
