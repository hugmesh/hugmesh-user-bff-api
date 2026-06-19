package systems.snapdragon.userbff.profile;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.data.r2dbc.DataR2dbcTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpStatus;
import systems.snapdragon.userbff.support.TestDatabaseConfig;
import systems.snapdragon.commons.web.ApiException;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * RESERVED-USERNAME validation for {@link ProfileService#save(String, String, UserProfile)}
 * over the real repository slice (H2 PostgreSQL-compat + the 004 changeset). Proves
 * the SERVICE-LAYER guard: a caller whose username is a reserved label cannot enable
 * a vanity subdomain or make their profile public (400), while a normal username can;
 * and that a non-vanity, non-public save with a reserved username is still allowed
 * (the reservation only matters once the username would become a public DNS label).
 */
@DataR2dbcTest
@Import({TestDatabaseConfig.class, UserProfileRepository.class,
        ProfileServiceReservedUsernameTest.StubCasdoor.class, ProfileService.class})
class ProfileServiceReservedUsernameTest {

    @TestConfiguration(proxyBeanMethods = false)
    static class StubCasdoor {
        @Bean CasdoorUserClient casdoorUserClient() { return new CasdoorUserClient(null, "snapdragon"); }
    }

    @Autowired ProfileService profiles;
    @Autowired UserProfileRepository repo;

    static Set<String> reservedLabels() {
        return ReservedNames.RESERVED_LABELS;
    }

    @ParameterizedTest
    @MethodSource("reservedLabels")
    void enablingVanity_withReservedUsername_isRejected400(String reserved) {
        // owner is a Casdoor SUBJECT (opaque) — username is the reserved label.
        UserProfile body = new UserProfile("sub-1", null, null, null, "X", "internal", true);
        assertThatThrownBy(() -> profiles.save("sub-1", reserved, body).block())
                .isInstanceOfSatisfying(ApiException.class,
                        ex -> assertThat(ex.status()).isEqualTo(HttpStatus.BAD_REQUEST));
        // nothing persisted
        assertThat(repo.find("sub-1").blockOptional()).isEmpty();
    }

    @ParameterizedTest
    @MethodSource("reservedLabels")
    void publicProfile_withReservedUsername_isRejected400(String reserved) {
        UserProfile body = new UserProfile("sub-2", null, null, null, "X", "public", false);
        assertThatThrownBy(() -> profiles.save("sub-2", reserved, body).block())
                .isInstanceOfSatisfying(ApiException.class,
                        ex -> assertThat(ex.status()).isEqualTo(HttpStatus.BAD_REQUEST));
        assertThat(repo.find("sub-2").blockOptional()).isEmpty();
    }

    @Test
    void caseInsensitive_reservedUsername_isRejected() {
        UserProfile body = new UserProfile("sub-3", null, null, null, "X", "internal", true);
        assertThatThrownBy(() -> profiles.save("sub-3", "ADMIN", body).block())
                .isInstanceOf(ApiException.class);
    }

    @Test
    void normalUsername_enablingVanity_isAllowed_andMirrorsVanityUsername() {
        UserProfile body = new UserProfile("sub-4", null, null, null, "Carol", "public", true);
        UserProfile saved = profiles.save("sub-4", "Carol", body).block();

        // persisted under the SUBJECT, with the normalized (lower-cased) vanity username
        assertThat(saved.userId()).isEqualTo("sub-4");
        assertThat(saved.vanityUsername()).isEqualTo("carol");
        UserProfile got = repo.find("sub-4").block();
        assertThat(got.vanityUsername()).isEqualTo("carol");
        assertThat(got.vanitySubdomainEnabled()).isTrue();
    }

    @Test
    void reservedUsername_butVanityDisabledAndInternal_isAllowed_noVanityUsername() {
        // The reservation only bites when the username would become a public DNS
        // label. A private, vanity-off profile for a user who happens to be named
        // 'admin' is still allowed; vanity_username stays NULL.
        UserProfile body = new UserProfile("sub-5", null, null, null, "Adminish", "internal", false);
        UserProfile saved = profiles.save("sub-5", "admin", body).block();
        assertThat(saved.vanityUsername()).isNull();
        assertThat(repo.find("sub-5").block().vanityUsername()).isNull();
    }
}
