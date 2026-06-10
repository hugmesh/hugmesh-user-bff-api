package systems.snapdragon.userbff.web;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.ConstraintViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.bind.support.WebExchangeBindException;
import org.springframework.web.server.ServerWebInputException;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.TreeMap;

/**
 * Renders {@link ApiException} as the {@code {"error": message}} JSON body (and
 * the carried status) the UIs read, AND maps jakarta Bean Validation failures to a
 * clean {@code 400} in the SAME shape (with a {@code fields} map of per-field
 * errors). Works unchanged under WebFlux: {@code @RestControllerAdvice} +
 * {@code @ExceptionHandler} returning a {@code ResponseEntity} is handled
 * reactively (a controller's {@code Mono.error(...)} is routed here).
 *
 * <p>Validation shapes handled (the security-hardening "Bean Validation on all
 * paths" task):
 * <ul>
 *   <li>{@link WebExchangeBindException} — a {@code @Valid @RequestBody} DTO whose
 *       field constraints failed;</li>
 *   <li>{@link ConstraintViolationException} — a {@code @Validated} controller's
 *       {@code @PathVariable}/{@code @RequestParam} constraint failed;</li>
 *   <li>{@link ServerWebInputException} — a malformed/missing body or an
 *       unparseable param (surface as 400, not 500).</li>
 * </ul>
 */
@RestControllerAdvice
public class ApiExceptionHandler {

    @ExceptionHandler(ApiException.class)
    public ResponseEntity<Map<String, Object>> handle(ApiException ex) {
        return ResponseEntity.status(ex.status()).body(Map.of("error", ex.getMessage()));
    }

    /** A {@code @Valid @RequestBody} DTO failed field validation. */
    @ExceptionHandler(WebExchangeBindException.class)
    public ResponseEntity<Map<String, Object>> handleBodyValidation(WebExchangeBindException ex) {
        Map<String, String> fields = new TreeMap<>();
        for (FieldError fe : ex.getFieldErrors()) {
            fields.putIfAbsent(fe.getField(), fe.getDefaultMessage() == null ? "invalid" : fe.getDefaultMessage());
        }
        return badRequest(fields);
    }

    /** A {@code @Validated} {@code @PathVariable}/{@code @RequestParam} failed. */
    @ExceptionHandler(ConstraintViolationException.class)
    public ResponseEntity<Map<String, Object>> handleParamValidation(ConstraintViolationException ex) {
        Map<String, String> fields = new TreeMap<>();
        for (ConstraintViolation<?> v : ex.getConstraintViolations()) {
            fields.putIfAbsent(lastNode(v), v.getMessage());
        }
        return badRequest(fields);
    }

    /**
     * A malformed/missing body or an unparseable param (e.g. wrong content-type, a
     * missing required body) — 400, not 500. {@link WebExchangeBindException}
     * subclasses this, so the more-specific handler above wins for DTO validation.
     */
    @ExceptionHandler(ServerWebInputException.class)
    public ResponseEntity<Map<String, Object>> handleInput(ServerWebInputException ex) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", "validation failed");
        body.put("detail", ex.getReason() == null ? "malformed request" : ex.getReason());
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(body);
    }

    private static ResponseEntity<Map<String, Object>> badRequest(Map<String, String> fields) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", "validation failed");
        body.put("fields", fields);
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(body);
    }

    /** The leaf property of a constraint-violation path = the param/field name. */
    private static String lastNode(ConstraintViolation<?> v) {
        String path = v.getPropertyPath().toString();
        int dot = path.lastIndexOf('.');
        return dot >= 0 ? path.substring(dot + 1) : path;
    }
}
