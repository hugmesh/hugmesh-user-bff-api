package systems.hugmesh.userbff.profile;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpStatus;
import reactor.core.publisher.Mono;
import systems.hugmesh.commons.web.ApiException;
import systems.hugmesh.userbff.federation.FederationApiClient;
import systems.hugmesh.userbff.support.TestDatabaseConfig;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * The cross-service VANITY PUBLISH sync — {@link ProfileService#save} calling
 * {@link FederationApiClient#publishVanity} / {@link FederationApiClient#unpublishVanity}
 * — over the real repository slice (H2 + the 004 changeset). This is the "missing
 * link" the federation-api README's <em>Vanity PUBLISH path (cross-service)</em>
 * section called out: flipping {@code visibility=public && vanitySubdomainEnabled}
 * previously persisted the flags locally but made NO federation call.
 *
 * <p>{@link FederationApiClient} is MOCKED here (not the shared always-succeeds
 * {@code StubFederationApiClient}) so each test can assert exactly what was called,
 * and can inject a federation FAILURE to prove it is never swallowed into a
 * fabricated "saved" success.
 */
@DataR2dbcTest
@Import({TestDatabaseConfig.class, UserProfileRepository.class,
        ProfileServiceFederationSyncTest.StubCasdoor.class,
        ProfileServiceFederationSyncTest.MockFederation.class, ProfileService.class})
class ProfileServiceFederationSyncTest {

    @TestConfiguration(proxyBeanMethods = false)
    static class StubCasdoor {
        @Bean CasdoorUserClient casdoorUserClient() { return new CasdoorUserClient(null, "hugmesh"); }
    }

    /** A raw Mockito mock (not the shared always-succeeds stub) so every test here
     *  can assert exactly what federation call was (or wasn't) made and drive
     *  failure legs. */
    @TestConfiguration(proxyBeanMethods = false)
    static class MockFederation {
        @Bean FederationApiClient federationApiClient() { return mock(FederationApiClient.class); }
    }

    @Autowired ProfileService profiles;
    @Autowired UserProfileRepository repo;
    @Autowired FederationApiClient federation;

    /** The {@code @DataR2dbcTest} context (and so this mock BEAN instance) is cached
     *  and REUSED across every test method in this class — reset its recorded
     *  invocations before each test so assertions never see a prior test's calls. */
    @BeforeEach
    void resetFederationMock() {
        org.mockito.Mockito.reset(federation);
    }

    private static UserProfile body(String owner, String displayName, String visibility, boolean vanity) {
        return new UserProfile(owner, null, null, null, displayName, visibility, vanity);
    }

    // ---- publish: vanity=true && visibility=public ----

    @Test
    void publicVanityProfile_callsFederationPublish_withNormalizedUsernameAndDisplayName() {
        when(federation.publishVanity(eq("alice"), eq("Alice"))).thenReturn(Mono.just(Map.of()));

        UserProfile saved = profiles.save("sub-1", "Alice", body("sub-1", "Alice", "public", true), "default")
                .block();

        assertThat(saved.vanityUsername()).isEqualTo("alice");
        // the USERNAME argument is normalized (lower-cased) — matches vanity_username.
        verify(federation).publishVanity("alice", "Alice");
        verify(federation, never()).unpublishVanity(any());
    }

    @Test
    void publish_username_isNormalized_evenWhenCasdoorClaimIsMixedCase() {
        when(federation.publishVanity(any(), any())).thenReturn(Mono.just(Map.of()));

        profiles.save("sub-mixed", "AlICe", body("sub-mixed", "Alice", "public", true), "default").block();

        verify(federation).publishVanity("alice", "Alice");
    }

    // ---- unpublish: NOT (vanity && public) ----

    @Test
    void internalProfile_withVanityDisabled_callsFederationUnpublish_notPublish() {
        when(federation.unpublishVanity(eq("bob"))).thenReturn(Mono.empty());

        profiles.save("sub-2", "bob", body("sub-2", "Bob", "internal", false), "default").block();

        verify(federation).unpublishVanity("bob");
        verify(federation, never()).publishVanity(any(), any());
    }

    @Test
    void publicVisibility_butVanityDisabled_stillUnpublishes_noDnsLabelToPublishUnder() {
        // visibility=public but vanitySubdomainEnabled=false: no vanity_username is
        // ever set (see UserProfile#withVanityUsername), so there is nothing to
        // register a federation fragment under — sync converges to unpublish.
        when(federation.unpublishVanity(eq("carol"))).thenReturn(Mono.empty());

        UserProfile saved = profiles.save("sub-3", "carol", body("sub-3", "Carol", "public", false), "default")
                .block();

        assertThat(saved.vanityUsername()).isNull();
        verify(federation).unpublishVanity("carol");
        verify(federation, never()).publishVanity(any(), any());
    }

    // ---- back-compat overload (no username threaded) never syncs ----

    @Test
    void backCompatOverload_noUsernameThreaded_neverCallsFederation() {
        profiles.save("sub-4", body("sub-4", "Dave", "internal", false)).block();

        verify(federation, never()).publishVanity(any(), any());
        verify(federation, never()).unpublishVanity(any());
    }

    // ---- honest failure propagation ----

    @Test
    void federationPublishFailure_failsTheSaveCall_neverReportsSuccess() {
        when(federation.publishVanity(eq("erin"), any())).thenReturn(
                Mono.error(new ApiException(HttpStatus.NOT_FOUND,
                        "no uploaded bundle for profile-erin")));

        assertThatThrownBy(() ->
                profiles.save("sub-5", "erin", body("sub-5", "Erin", "public", true), "default").block())
                .isInstanceOfSatisfying(ApiException.class,
                        ex -> assertThat(ex.status()).isEqualTo(HttpStatus.NOT_FOUND));

        // the LOCAL row still reflects the caller's request (best-effort local write;
        // the federation failure is what's surfaced, not a rollback) — but the
        // OVERALL save() call reported the true failure, never a fabricated success.
        assertThat(repo.find("sub-5").block().visibility()).isEqualTo("public");
    }

    /**
     * ASYMMETRIC by design: unlike publish, an unpublish failure does NOT fail the
     * save — see the class Javadoc / {@code ProfileService#syncVanityPublish}. The
     * unpublish leg fires on EVERY non-public save (most of which never touched
     * vanity at all), so a federation-api outage must never block an unrelated
     * profile edit. The local row (this platform's own source of truth for
     * visibility) is already correctly private the moment save() returns.
     */
    @Test
    void federationUnpublishFailure_isBestEffort_saveStillSucceeds() {
        when(federation.unpublishVanity(eq("frank"))).thenReturn(
                Mono.error(new ApiException(HttpStatus.SERVICE_UNAVAILABLE, "federation down")));

        UserProfile saved = profiles.save("sub-6", "frank", body("sub-6", "Frank", "internal", false), "default")
                .block();

        assertThat(saved.visibility()).isEqualTo("internal");
        assertThat(repo.find("sub-6").block().visibility()).isEqualTo("internal");
        verify(federation).unpublishVanity("frank");
    }

    // ---- republish / re-unpublish on subsequent saves (idempotent-shaped) ----

    @Test
    void togglingVanityOffThenOn_callsUnpublishThenPublish_inOrder() {
        when(federation.unpublishVanity(eq("gina"))).thenReturn(Mono.empty());
        when(federation.publishVanity(eq("gina"), any())).thenReturn(Mono.just(Map.of()));

        // first save: private
        profiles.save("sub-7", "gina", body("sub-7", "Gina", "internal", false), "default").block();
        // second save: opts into public + vanity
        profiles.save("sub-7", "gina", body("sub-7", "Gina", "public", true), "default").block();

        verify(federation, times(1)).unpublishVanity("gina");
        verify(federation, times(1)).publishVanity("gina", "Gina");
    }
}
