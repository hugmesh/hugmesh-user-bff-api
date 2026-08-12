package net.hugmesh.userbff.silence;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.time.Instant;

/**
 * One self-silence belonging to the caller (table {@code self_silence}). The user
 * has made THEMSELVES invisible to others until {@link #expiresAt()}; they keep
 * their session and full access the whole time. {@code userId} is the owner = the
 * Casdoor JWT subject; a user has at most one row (PK on {@code userId}).
 *
 * <p>A self-silence is the source of truth and is structurally DISTINCT from a ban:
 * it carries NO Casdoor role change, NO {@code access_suspension} row, and NO
 * revocation key (see {@link SelfSilenceService}). {@link #active()} derives the
 * effective state from the row alone ({@code cleared_at IS NULL AND now < expiresAt}).
 *
 * <p>{@code userId} is never accepted from the request body — the controller always
 * sets it from the JWT subject, so a user can only ever silence themselves.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record SelfSilence(
        String userId,
        Instant startedAt,
        Instant expiresAt,
        Instant clearedAt,
        String reason,
        Instant updatedAt) {

    /**
     * Whether this silence is currently in effect: not yet cleared AND not yet past
     * its expiry. The scheduled wake clears expired rows, but a status read may see
     * an overdue-but-uncleared row between ticks — {@code active()} treats that as
     * inactive so the user is never told they are still hidden after expiry.
     */
    public boolean active() {
        return clearedAt == null && expiresAt != null && Instant.now().isBefore(expiresAt);
    }
}
