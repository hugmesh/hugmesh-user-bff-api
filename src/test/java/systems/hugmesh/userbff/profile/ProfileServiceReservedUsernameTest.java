package systems.hugmesh.userbff.profile;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpStatus;
import systems.hugmesh.userbff.support.StubFederationApiClient;
import systems.hugmesh.userbff.support.TestDatabaseConfig;
import systems.hugmesh.authcore.reserved.ReservedNames;
import systems.hugmesh.commons.web.ApiException;

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
        ProfileServiceReservedUsernameTest.StubCasdoor.class, StubFederationApiClient.class,
        ProfileService.class})
class ProfileServiceReservedUsernameTest {

    @TestConfiguration(proxyBeanMethods = false)
    static class StubCasdoor {
        @Bean CasdoorUserClient casdoorUserClient() { return new CasdoorUserClient(null, "hugmesh"); }
    }

    @Autowired ProfileService profiles;
    @Autowired UserProfileRepository repo;

    static Set<String> reservedLabels() {
        return ReservedNames.RESERVED;
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

    /**
     * The canonical revision 7-9 labels — {@code hmdm}/{@code attest} (Headwind MDM +
     * AttestationServer superadmin-gateway route prefixes) and the Character Forge
     * track's {@code character-forge}/{@code games-character-forge}/
     * {@code games-shadows-of-the-net} — are enforced AT RUNTIME by the pinned
     * auth-core (2.4.1). Named explicitly here (not only via the RESERVED
     * {@code @MethodSource} iteration above) so a pin downgrade to a pre-revision-9
     * auth-core fails THIS test with the missing label's name instead of silently
     * shrinking the parameterised set. Before 2.4.1 these five were enforced only by
     * the 021 DB CHECK backstop; the service layer now rejects them as a clean 400.
     */
    @ParameterizedTest
    @ValueSource(strings = {"hmdm", "attest", "character-forge",
            "games-character-forge", "games-shadows-of-the-net"})
    void canonicalRev7To9Label_enablingVanityOrPublic_isRejected400AtServiceLayer(String reserved) {
        assertThat(ReservedNames.RESERVED).contains(reserved);
        assertThat(ReservedNames.isReserved(reserved)).isTrue();

        UserProfile body = new UserProfile("sub-r9", null, null, null, "X", "public", true);
        assertThatThrownBy(() -> profiles.save("sub-r9", reserved, body).block())
                .isInstanceOfSatisfying(ApiException.class,
                        ex -> assertThat(ex.status()).isEqualTo(HttpStatus.BAD_REQUEST));
        assertThat(repo.find("sub-r9").blockOptional()).isEmpty();
    }

    @Test
    void caseInsensitive_reservedUsername_isRejected() {
        UserProfile body = new UserProfile("sub-3", null, null, null, "X", "internal", true);
        assertThatThrownBy(() -> profiles.save("sub-3", "ADMIN", body).block())
                .isInstanceOf(ApiException.class);
    }

    /**
     * INTENTIONAL behaviour delta from the deleted local dup: the canonical auth-core
     * {@link ReservedNames} additionally treats the platform-internal {@code "system"}
     * principal as reserved (via {@code RESERVED_PLATFORM_INTERNAL} — NOT a member of
     * the route-derived {@link ReservedNames#RESERVED} set the parameterised cases above
     * iterate, so it is asserted here explicitly). Enabling a {@code system} vanity
     * subdomain must be rejected 400 so the @system notification/infra accounts can
     * never be impersonated by a vanity profile.
     */
    @Test
    void platformInternalSystemUsername_enablingVanity_isRejected400() {
        assertThat(ReservedNames.RESERVED).doesNotContain("system");
        assertThat(ReservedNames.isReserved("system")).isTrue();

        UserProfile body = new UserProfile("sub-6", null, null, null, "X", "internal", true);
        assertThatThrownBy(() -> profiles.save("sub-6", "system", body).block())
                .isInstanceOfSatisfying(ApiException.class,
                        ex -> assertThat(ex.status()).isEqualTo(HttpStatus.BAD_REQUEST));
        assertThat(repo.find("sub-6").blockOptional()).isEmpty();
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
