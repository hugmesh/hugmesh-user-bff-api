package net.hugmesh.userbff.profile;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpStatus;
import net.hugmesh.userbff.support.StubFederationApiClient;
import net.hugmesh.userbff.support.TestDatabaseConfig;
import net.hugmesh.commons.web.ApiException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Service-layer tests for the TWO impersonation-gap fixes over the real repository
 * slice (H2 + the 004 changeset):
 *
 * <ul>
 *   <li><b>GAP 1</b> — the {@code save(owner, body)} overload (username=null) no
 *       longer SKIPS the guards: the displayName charset/confusable guard runs on it
 *       too, so an impersonation displayName cannot be smuggled through the overload
 *       that the controller's vanity path doesn't use.</li>
 *   <li><b>GAP 2</b> — {@code displayName} (free text) is rejected when it carries a
 *       zero-width / bidi / format code point, or is confusable with a reserved
 *       label; a normal displayName saves fine. The username vanity path also now
 *       rejects reserved-CONFUSABLE usernames (4dmin, ad-min, Cyrillic admin), not
 *       just exact reserved labels.</li>
 * </ul>
 */
@DataR2dbcTest
@Import({TestDatabaseConfig.class, UserProfileRepository.class,
        ProfileServiceConfusableGuardTest.StubCasdoor.class, StubFederationApiClient.class,
        ProfileService.class})
class ProfileServiceConfusableGuardTest {

    @TestConfiguration(proxyBeanMethods = false)
    static class StubCasdoor {
        @Bean CasdoorUserClient casdoorUserClient() { return new CasdoorUserClient(null, "hugmesh"); }
    }

    @Autowired ProfileService profiles;
    @Autowired UserProfileRepository repo;

    // ---- GAP 2: displayName charset guard (zero-width / bidi) ----

    @ParameterizedTest
    @ValueSource(strings = {
            "ad​min",   // ZERO WIDTH SPACE inside a name
            "Ali‍ce",   // ZERO WIDTH JOINER
            "﻿Eve",     // BOM / ZWNBSP
            "test‮moc", // RIGHT-TO-LEFT OVERRIDE (bidi spoof)
    })
    void displayName_withInvisibleOrBidi_isRejected400(String badName) {
        UserProfile body = new UserProfile("sub-zw", null, null, null, badName, "internal", false);
        assertThatThrownBy(() -> profiles.save("sub-zw", body).block())
                .isInstanceOfSatisfying(ApiException.class,
                        ex -> assertThat(ex.status()).isEqualTo(HttpStatus.BAD_REQUEST));
        // nothing persisted — the guard fired before the write
        assertThat(repo.find("sub-zw").blockOptional()).isEmpty();
    }

    // ---- GAP 2: displayName confusable-of-reserved guard ----

    @ParameterizedTest
    @ValueSource(strings = {"admin", "4dmin", "Admin", "ad-min", "аdmin" /* Cyrillic а */})
    void displayName_confusableWithReserved_isRejected400(String impersonation) {
        UserProfile body = new UserProfile("sub-imp", null, null, null, impersonation, "internal", false);
        assertThatThrownBy(() -> profiles.save("sub-imp", body).block())
                .isInstanceOfSatisfying(ApiException.class,
                        ex -> assertThat(ex.status()).isEqualTo(HttpStatus.BAD_REQUEST));
        assertThat(repo.find("sub-imp").blockOptional()).isEmpty();
    }

    @Test
    void displayName_normal_isAllowed() {
        // "Anna Müller" is non-ASCII (the ü), so the a11y flow now requires an ASCII
        // screen-reader name (a 422 prompt otherwise — covered by
        // ProfileServiceScreenReaderNameTest). Supply one so THIS test isolates the
        // displayName confusable guard: a normal display name is not rejected by it.
        UserProfile body = new UserProfile("sub-ok", null, null, null, "Anna Müller",
                "internal", false, null, "Anna Mueller");
        UserProfile saved = profiles.save("sub-ok", body).block();
        assertThat(saved.displayName()).isEqualTo("Anna Müller");
        assertThat(repo.find("sub-ok").block().displayName()).isEqualTo("Anna Müller");
        assertThat(saved.screenReaderName()).isEqualTo("Anna Mueller");
    }

    // ---- GAP 1: the save(owner, body) overload now applies the guard ----

    @Test
    void saveOverload_nullUsername_stillGuardsDisplayName() {
        // The two-arg overload threads username=null; it must NOT skip the displayName
        // guard (the gap). An impersonation displayName via this overload is rejected.
        UserProfile body = new UserProfile("sub-gap", null, null, null, "admin", "internal", false);
        assertThatThrownBy(() -> profiles.save("sub-gap", body).block())
                .isInstanceOf(ApiException.class);
        assertThat(repo.find("sub-gap").blockOptional()).isEmpty();
    }

    @Test
    void saveOverload_zeroWidthDisplayName_isRejected() {
        UserProfile body = new UserProfile("sub-gap2", null, null, null, "Ali​ce", "public", true);
        assertThatThrownBy(() -> profiles.save("sub-gap2", body).block())
                .isInstanceOf(ApiException.class);
        assertThat(repo.find("sub-gap2").blockOptional()).isEmpty();
    }

    // ---- GAP 2 (username side): reserved-CONFUSABLE username on the vanity path ----

    @ParameterizedTest
    @ValueSource(strings = {"4dmin", "ad-min", "r00t", "аdmin" /* Cyrillic admin */})
    void enablingVanity_withReservedConfusableUsername_isRejected400(String confusable) {
        UserProfile body = new UserProfile("sub-cf", null, null, null, "Carol", "internal", true);
        assertThatThrownBy(() -> profiles.save("sub-cf", confusable, body).block())
                .isInstanceOfSatisfying(ApiException.class,
                        ex -> assertThat(ex.status()).isEqualTo(HttpStatus.BAD_REQUEST));
        assertThat(repo.find("sub-cf").blockOptional()).isEmpty();
    }

    @Test
    void normalUsername_andNormalDisplayName_savesWithVanity() {
        UserProfile body = new UserProfile("sub-good", null, null, null, "Carol", "public", true);
        UserProfile saved = profiles.save("sub-good", "carol", body).block();
        assertThat(saved.vanityUsername()).isEqualTo("carol");
        assertThat(saved.displayName()).isEqualTo("Carol");
    }
}
