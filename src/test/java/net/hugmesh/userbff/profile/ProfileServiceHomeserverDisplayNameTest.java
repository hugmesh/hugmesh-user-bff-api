package net.hugmesh.userbff.profile;

import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import net.hugmesh.userbff.federation.FederationApiClient;
import net.hugmesh.userbff.hsproxy.ServiceTokenBroker;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * The user-bff profile {@code displayName} is the source of truth for a name the person chose;
 * before this, a saved name never left user-bff, so Matrix and Mastodon/Akkoma kept showing the
 * account's UUID localpart. A save now hands the name to the homeserver push, after the local
 * write, and a failing push never fails the save.
 */
class ProfileServiceHomeserverDisplayNameTest {

    private static final String OWNER = "casdoor:c18f905c-62a1-4c20-a7c5-c707fb6eae85";

    private final UserProfileRepository repo = mock(UserProfileRepository.class);
    private final FederationApiClient federation = mock(FederationApiClient.class);
    private final ServiceTokenBroker broker = mock(ServiceTokenBroker.class);

    private ProfileService service() {
        when(repo.save(any(UserProfile.class), any())).thenAnswer(inv -> Mono.just(inv.getArgument(0)));
        when(federation.unpublishVanity(anyString())).thenReturn(Mono.empty());
        return new ProfileService(repo, mock(CasdoorUserClient.class), federation, broker);
    }

    private static UserProfile named(String displayName) {
        return new UserProfile(null, null, null, null, displayName, "internal", false);
    }

    @Test
    void save_pushesTheChosenDisplayNameToTheHomeservers() {
        when(broker.pushChosenDisplayName(anyString(), anyString())).thenReturn(Mono.empty());

        StepVerifier.create(service().save(OWNER, "e2e-matrix", named("Matrix Tester")))
                .expectNextCount(1).verifyComplete();

        verify(broker).pushChosenDisplayName(eq(OWNER), eq("Matrix Tester"));
    }

    @Test
    void save_withoutADisplayName_pushesNothing() {
        StepVerifier.create(service().save(OWNER, "e2e-matrix", named(null)))
                .expectNextCount(1).verifyComplete();

        verify(broker, never()).pushChosenDisplayName(anyString(), anyString());
    }

    @Test
    void save_succeedsEvenWhenThePushFails() {
        when(broker.pushChosenDisplayName(anyString(), anyString()))
                .thenReturn(Mono.error(new IllegalStateException("homeserver down")));

        StepVerifier.create(service().save(OWNER, "e2e-matrix", named("Matrix Tester")))
                .expectNextCount(1).verifyComplete();
    }
}
