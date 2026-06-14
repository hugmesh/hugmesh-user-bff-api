package systems.snapdragon.userbff.notification;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/**
 * Deterministic {@code user_notifications.id} for the internal deliver path so a
 * RETRIED delivery of the SAME source event is an INSERT-IF-ABSENT (idempotent) — a
 * duplicate call can never create a second inbox row.
 *
 * <p>The id is a stable hash of {@code sourceTable + '|' + sourceId + '|in-app'}: the
 * {@code in-app} channel discriminator is part of the key so the SAME source event
 * routed to a DIFFERENT channel (a later PR's email/matrix delivery) gets a DIFFERENT
 * deterministic id and never collides with the in-app row. The source coordinates come
 * from the calling reconciler (which owns the source event), so the SAME (sourceTable,
 * sourceId) always maps to the SAME id across retries / pods / restarts — no shared
 * clock or counter, no DB round-trip to compute it.
 *
 * <p>SHA-256 of the UTF-8 key, hex-encoded and truncated to 32 chars (128 bits) — well
 * within the {@code varchar(64)} {@code id} PK column, with collision probability
 * negligible for the notification volume. A fixed, separator-delimited key shape means
 * two different events can never accidentally hash to the same id by component
 * concatenation (e.g. {@code ("ab","c")} vs {@code ("a","bc")}) because the {@code '|'}
 * delimiter is structural.
 */
public final class StableNotificationId {

    private StableNotificationId() {}

    /** The fixed in-app channel discriminator baked into the key. */
    public static final String IN_APP_CHANNEL = "in-app";

    /** Length (hex chars) the SHA-256 digest is truncated to — 128 bits, comfortably
     *  inside the varchar(64) id column. */
    private static final int ID_HEX_LEN = 32;

    /**
     * The deterministic in-app id for one source event: {@code sha256(sourceTable +
     * '|' + sourceId + '|in-app')[:32]}. Both source coordinates are required (the
     * service rejects a blank one before calling this), so the key is never ambiguous.
     */
    public static String forInApp(String sourceTable, String sourceId) {
        String key = sourceTable + "|" + sourceId + "|" + IN_APP_CHANNEL;
        return sha256Hex(key).substring(0, ID_HEX_LEN);
    }

    private static String sha256Hex(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(input.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 is mandated by every JVM — unreachable.
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}
