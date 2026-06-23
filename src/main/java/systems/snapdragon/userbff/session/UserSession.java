package systems.snapdragon.userbff.session;

import java.time.LocalDateTime;

/**
 * The caller-safe view of ONE of the caller's own opaque {@code bff_} sessions, as returned
 * to the browser by {@code GET /bff/user/sessions}.
 *
 * <p>SECURITY — the raw {@code bff_} session token is a LIVE bearer credential: presenting
 * it as {@code Authorization: Bearer bff_<token>} authenticates as the owner. So it is NEVER
 * placed in this DTO. Instead {@link #id} is an OPAQUE, deterministic fingerprint of the raw
 * token (a SHA-256 hex digest); it is safe to render in a browser and is the handle the
 * client passes back to {@code DELETE /bff/user/sessions/{id}} to revoke a session. The
 * server re-derives the same fingerprint over the caller's OWN live tokens to resolve the
 * id back to a raw token for the admin-bff revoke call — so the raw token never leaves the
 * server boundary, and an id for a session the caller does not own can never be resolved.
 *
 * @param id        opaque SHA-256 fingerprint of the raw session token (NOT the token)
 * @param createdAt when the session was minted
 * @param expiresAt when the session expires
 */
public record UserSession(String id, LocalDateTime createdAt, LocalDateTime expiresAt) {
}
