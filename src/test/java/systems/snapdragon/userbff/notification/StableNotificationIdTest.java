package systems.snapdragon.userbff.notification;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit test for {@link StableNotificationId} — the deterministic in-app id that makes
 * the internal deliver path idempotent (a retry of the same source event hashes to the
 * SAME id, so the insert is INSERT-IF-ABSENT).
 */
class StableNotificationIdTest {

    @Test
    void sameSource_sameId() {
        assertThat(StableNotificationId.forInApp("role_grant", "rg-1"))
                .isEqualTo(StableNotificationId.forInApp("role_grant", "rg-1"));
    }

    @Test
    void differentSourceId_differentId() {
        assertThat(StableNotificationId.forInApp("role_grant", "rg-1"))
                .isNotEqualTo(StableNotificationId.forInApp("role_grant", "rg-2"));
    }

    @Test
    void differentSourceTable_differentId() {
        assertThat(StableNotificationId.forInApp("role_grant", "x"))
                .isNotEqualTo(StableNotificationId.forInApp("access_suspension", "x"));
    }

    @Test
    void delimiterIsStructural_noConcatenationCollision() {
        // ("ab","c") must NOT collide with ("a","bc") — the '|' delimiter is structural.
        assertThat(StableNotificationId.forInApp("ab", "c"))
                .isNotEqualTo(StableNotificationId.forInApp("a", "bc"));
    }

    @Test
    void idFitsIdColumn() {
        String id = StableNotificationId.forInApp("role_grant", "rg-1");
        assertThat(id).hasSize(32);                 // 128-bit hex, within varchar(64)
        assertThat(id).matches("^[0-9a-f]{32}$");   // lower-hex, no separators
    }
}
