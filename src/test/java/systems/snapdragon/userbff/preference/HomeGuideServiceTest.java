package systems.snapdragon.userbff.preference;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import systems.snapdragon.userbff.support.TestDatabaseConfig;
import systems.snapdragon.commons.web.ApiException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Home-guide dismiss ROUND-TRIP over the real {@link UserPreferenceRepository}
 * slice (H2-PG-compat + real Liquibase): first visit shows the guide (not
 * dismissed), dismiss persists, a second read sees it dismissed, reset re-shows it.
 * Also asserts per-guide keying + owner isolation.
 */
@DataR2dbcTest
@Import({TestDatabaseConfig.class, UserPreferenceRepository.class, HomeGuideService.class})
class HomeGuideServiceTest {

    @Autowired HomeGuideService guides;

    @Test
    void dismissRoundTrip_firstVisitThenDismissedThenReset() {
        // first visit — not dismissed
        assertThat(guides.isDismissed("alice", "home").block()).isFalse();
        // dismiss persists
        guides.dismiss("alice", "home").block();
        assertThat(guides.isDismissed("alice", "home").block()).isTrue();
        // idempotent re-dismiss
        guides.dismiss("alice", "home").block();
        assertThat(guides.isDismissed("alice", "home").block()).isTrue();
        // reset re-shows
        guides.reset("alice", "home").block();
        assertThat(guides.isDismissed("alice", "home").block()).isFalse();
    }

    @Test
    void perGuideKeying_independent() {
        guides.dismiss("alice", "user-home").block();
        assertThat(guides.isDismissed("alice", "user-home").block()).isTrue();
        // a different guide for the same user is still shown
        assertThat(guides.isDismissed("alice", "settings").block()).isFalse();
    }

    @Test
    void ownerIsolation_dismissDoesNotLeakAcrossUsers() {
        guides.dismiss("alice", "home").block();
        assertThat(guides.isDismissed("bob", "home").block()).isFalse();
    }

    @Test
    void blankOwner_rejected() {
        assertThatThrownBy(() -> guides.isDismissed("", "home"))
                .isInstanceOf(ApiException.class);
    }
}
