package net.hugmesh.userbff.profile;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.boot.test.context.TestConfiguration;
import net.hugmesh.userbff.support.StubFederationApiClient;
import net.hugmesh.userbff.support.TestDatabaseConfig;
import net.hugmesh.commons.web.ApiException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * OWNER-ENFORCEMENT test for {@link ProfileService} over the real repository slice.
 * The critical guarantee: a user can only read/write their OWN profile. The body's
 * {@code userId} is IGNORED — {@code save(owner, body)} always persists under the
 * caller, so a malicious body cannot redirect the write to another user's row.
 */
@DataR2dbcTest
@Import({TestDatabaseConfig.class, UserProfileRepository.class,
        ProfileServiceOwnerEnforcementTest.StubCasdoor.class, StubFederationApiClient.class,
        ProfileService.class})
class ProfileServiceOwnerEnforcementTest {

    @TestConfiguration(proxyBeanMethods = false)
    static class StubCasdoor {
        /** Stubbed (null WebClient) Casdoor client — no live IdP write in tests. */
        @Bean CasdoorUserClient casdoorUserClient() { return new CasdoorUserClient(null, "hugmesh"); }
    }

    @Autowired ProfileService profiles;
    @Autowired UserProfileRepository repo;

    @Test
    void save_ignoresBodyUserId_andWritesUnderCaller() {
        // alice submits a body that LIES about the userId, trying to write as "bob".
        // vanitySubdomainEnabled stays FALSE here: this overload threads no username, and a
        // vanity subdomain with no DNS label to make it out of is now refused outright
        // (see saveWithVanity_butNoUsernameThreaded_failsClosed below). The spoof axis under
        // test — the body's userId — is unchanged.
        UserProfile spoof = new UserProfile("bob", null, "she/her", null, "Mallory", "public", false);
        UserProfile saved = profiles.save("alice", spoof).block();

        // persisted under alice, NOT bob
        assertThat(saved.userId()).isEqualTo("alice");
        assertThat(repo.find("alice").block().displayName()).isEqualTo("Mallory");
        // bob's row was never created/touched
        assertThat(repo.find("bob").blockOptional()).isEmpty();
    }

    /**
     * FAIL CLOSED: a vanity SUBDOMAIN is a DNS label, so it cannot be granted without a
     * username to build one from. The previous behaviour persisted
     * {@code vanity_subdomain_enabled=true} with a NULL {@code vanity_username} — a row
     * claiming a subdomain that nothing could ever resolve — and skipped the federation
     * publish in silence.
     *
     * <p>This is the reachable case now that {@link ProfileController#usernameOf} returns
     * {@code null} rather than handing on a composite account id or an email address: a
     * {@code bff_} session whose account handle is email-keyed threads no username at all.
     */
    @Test
    void saveWithVanity_butNoUsernameThreaded_failsClosed_andWritesNothing() {
        UserProfile wantsVanity = new UserProfile("vanity-nouser", null, null, null, "Alice", "public", true);

        assertThatThrownBy(() -> profiles.save("vanity-nouser", wantsVanity).block())
                .isInstanceOfSatisfying(ApiException.class, ex -> {
                    assertThat(ex.status().value()).isEqualTo(400);
                    assertThat(ex.getMessage()).contains("no username on the caller's token");
                });

        // and NOTHING was persisted — not even a half-row with vanity enabled
        assertThat(repo.find("vanity-nouser").blockOptional()).isEmpty();
    }

    @Test
    void get_returnsOnlyOwnProfile_emptyDefaultOtherwise() {
        profiles.save("alice", new UserProfile("alice", null, null, null, "Alice", "internal", false)).block();
        // bob (no profile) gets an empty default keyed to bob — never alice's
        UserProfile bob = profiles.get("bob").block();
        assertThat(bob.userId()).isEqualTo("bob");
        assertThat(bob.displayName()).isNull();
        assertThat(bob.visibility()).isEqualTo(UserProfile.DEFAULT_VISIBILITY);
    }

    @Test
    void delete_onlyRemovesOwnRow() {
        profiles.save("alice", new UserProfile("alice", null, null, null, "Alice", "internal", false)).block();
        profiles.save("bob", new UserProfile("bob", null, null, null, "Bob", "internal", false)).block();
        profiles.delete("alice").block();
        assertThat(repo.find("alice").blockOptional()).isEmpty();
        assertThat(repo.find("bob").block().displayName()).isEqualTo("Bob");
    }

    @Test
    void changePassword_stubWiredFlow_noError() {
        // stub Casdoor — the reactive flow runs end to end without a live write.
        // owner = JWT subject; "alice" = the token's preferred_username (the Casdoor
        // login name the IdP write is addressed by — see ProfileServiceCasdoorIdentityTest).
        profiles.changePassword("subject-uuid", "alice", "old", "newpw").block();
        assertThat(profiles.casdoorEnabled()).isFalse();
    }

    @Test
    void changePassword_rejectsBlankNew() {
        assertThatThrownBy(() -> profiles.changePassword("subject-uuid", "alice", "old", " ").block())
                .isInstanceOf(ApiException.class);
    }

    @Test
    void changePassword_rejectsBlankUsername_failClosed() {
        // No Casdoor username on the token ⇒ the IdP write cannot be addressed. Fail
        // closed with a 400 — NEVER fall back to the subject (a UUID / provider:handle
        // composite Casdoor rejects as "user doesn't exist"; the pre-fix code sent
        // exactly that and the client swallowed the refusal into a success ack).
        assertThatThrownBy(() -> profiles.changePassword("subject-uuid", " ", "old", "newpw").block())
                .isInstanceOf(ApiException.class);
    }
}
