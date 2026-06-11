package systems.snapdragon.userbff.profile;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.data.r2dbc.DataR2dbcTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import systems.snapdragon.userbff.support.TestDatabaseConfig;
import systems.snapdragon.userbff.web.ApiException;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * SCREEN-READER NAME (a11y) default + prompt logic for {@link ProfileService} over the
 * real repository slice (008 {@code screen_reader_name} column applied by
 * TestDatabaseConfig). Asserts:
 * <ul>
 *   <li>an ASCII display name DEFAULTS the screen-reader name to itself (no prompt) and
 *       round-trips through the 008 column;</li>
 *   <li>a NON-ASCII display name with NO screen-reader name is a 422 PROMPT;</li>
 *   <li>a NON-ASCII display name WITH an ASCII screen-reader name saves;</li>
 *   <li>a present NON-ASCII screen-reader name is a 400 (charset, service leg);</li>
 *   <li>an explicitly-supplied screen-reader name is NOT overwritten by the default.</li>
 * </ul>
 */
@DataR2dbcTest
@Import({TestDatabaseConfig.class, UserProfileRepository.class,
        ProfileServiceScreenReaderNameTest.StubCasdoor.class, ProfileService.class})
class ProfileServiceScreenReaderNameTest {

    @TestConfiguration(proxyBeanMethods = false)
    static class StubCasdoor {
        @Bean CasdoorUserClient casdoorUserClient() { return new CasdoorUserClient(null, "snapdragon"); }
    }

    @Autowired ProfileService profiles;
    @Autowired UserProfileRepository repo;

    /** Build a profile body with the given display + screen-reader names. */
    private static UserProfile body(String owner, String displayName, String screenReaderName) {
        return new UserProfile(owner, null, null, null, displayName, "internal", false, null, screenReaderName);
    }

    @Test
    void asciiDisplayName_defaultsScreenReaderNameToIt() {
        UserProfile saved = profiles.save("alice", body("alice", "Alice", null)).block();
        assertThat(saved.screenReaderName()).isEqualTo("Alice");
        // round-trips through the 008 column
        assertThat(repo.find("alice").block().screenReaderName()).isEqualTo("Alice");
    }

    @Test
    void nonAsciiDisplayName_withoutScreenReaderName_isUnprocessable422() {
        ApiException ex = catchApiException(() -> profiles.save("bob", body("bob", "José", null)).block());
        assertThat(ex.status().value()).isEqualTo(422);
        // nothing persisted
        assertThat(repo.find("bob").blockOptional()).isEmpty();
    }

    @Test
    void nonAsciiDisplayName_withAsciiScreenReaderName_saves() {
        UserProfile saved = profiles.save("carol", body("carol", "José", "Jose")).block();
        assertThat(saved.displayName()).isEqualTo("José");
        assertThat(saved.screenReaderName()).isEqualTo("Jose");
        assertThat(repo.find("carol").block().screenReaderName()).isEqualTo("Jose");
    }

    @Test
    void nonAsciiScreenReaderName_isBadRequest400_serviceLeg() {
        // An ASCII display name with a NON-ASCII screen-reader name is a charset 400.
        ApiException ex = catchApiException(() -> profiles.save("dave", body("dave", "Dave", "Dävé")).block());
        assertThat(ex.status().value()).isEqualTo(400);
    }

    @Test
    void explicitAsciiScreenReaderName_isNotOverwrittenByDefault() {
        // ASCII display name would default to "Erin", but an explicit one wins.
        UserProfile saved = profiles.save("erin", body("erin", "Erin", "Erin Smith")).block();
        assertThat(saved.screenReaderName()).isEqualTo("Erin Smith");
    }

    @Test
    void noDisplayName_noScreenReaderName_isFine() {
        UserProfile saved = profiles.save("frank", body("frank", null, null)).block();
        assertThat(saved.screenReaderName()).isNull();
    }

    private static ApiException catchApiException(Runnable r) {
        try {
            r.run();
        } catch (ApiException e) {
            return e;
        }
        throw new AssertionError("expected an ApiException to be thrown");
    }
}
