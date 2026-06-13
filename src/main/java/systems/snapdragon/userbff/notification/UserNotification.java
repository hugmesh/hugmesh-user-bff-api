package systems.snapdragon.userbff.notification;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.time.Instant;

/**
 * One in-app notification belonging to the caller (table {@code user_notifications}) —
 * a row of the always-on in-app FLOOR inbox. The in-app channel can never be silenced
 * (the per-category prefs only gate the OTHER channels in later PRs), so this is the
 * floor every user always sees.
 *
 * <p>{@code userSubject} is the owner = the Casdoor JWT subject and is NEVER accepted
 * from a request body (the controller always sets it from the JWT subject), so a user
 * cannot read another user's notification. {@code readAt} is null until the owner marks
 * the row read.
 *
 * <p>SHIPS DARK in PR1: nothing writes this table yet — the snapdragon-actions
 * reconciler in a later PR is the only writer. This record is the read/mark-read side.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record UserNotification(
        String id,
        String userSubject,
        String category,
        String title,
        String body,
        Instant createdAt,
        Instant readAt) {
}
