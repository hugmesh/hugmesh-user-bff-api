package systems.snapdragon.userbff.web;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.Map;

/**
 * Renders {@link ApiException} as the {@code {"error": message}} JSON body (and
 * the carried status) the UIs read. Works unchanged under WebFlux:
 * {@code @RestControllerAdvice} + {@code @ExceptionHandler} returning a
 * {@code ResponseEntity} is handled reactively (a controller's
 * {@code Mono.error(ApiException)} is routed here).
 */
@RestControllerAdvice
public class ApiExceptionHandler {

    @ExceptionHandler(ApiException.class)
    public ResponseEntity<Map<String, Object>> handle(ApiException ex) {
        return ResponseEntity.status(ex.status()).body(Map.of("error", ex.getMessage()));
    }
}
