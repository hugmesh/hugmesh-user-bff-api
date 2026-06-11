package systems.snapdragon.userbff.web;

import org.springframework.http.HttpStatus;

/**
 * Carries an HTTP status + a message rendered as the {@code {"error": msg}} JSON
 * body the snapdragon UIs expect (matching the admin-bff reference). Thrown by the
 * user BFF controllers/services for application-level checks (owner mismatch,
 * not-found, bad upstream); handled by {@link ApiExceptionHandler}.
 */
public class ApiException extends RuntimeException {

    private final HttpStatus status;

    public ApiException(HttpStatus status, String message) {
        super(message);
        this.status = status;
    }

    public HttpStatus status() { return status; }

    public static ApiException unauthorized(String msg) { return new ApiException(HttpStatus.UNAUTHORIZED, msg); }
    public static ApiException forbidden(String msg)    { return new ApiException(HttpStatus.FORBIDDEN, msg); }
    public static ApiException notFound(String msg)     { return new ApiException(HttpStatus.NOT_FOUND, msg); }
    public static ApiException badRequest(String msg)   { return new ApiException(HttpStatus.BAD_REQUEST, msg); }
    public static ApiException badGateway(String msg)   { return new ApiException(HttpStatus.BAD_GATEWAY, msg); }

    /** 422 UNPROCESSABLE ENTITY — the request is syntactically valid but the flow
     *  cannot proceed as-is and needs more input (used to PROMPT for a screen-reader
     *  name when a non-ASCII display name has no ASCII spoken counterpart). */
    public static ApiException unprocessable(String msg) {
        return new ApiException(HttpStatus.UNPROCESSABLE_ENTITY, msg);
    }
}
