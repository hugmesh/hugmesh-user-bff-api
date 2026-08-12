package net.hugmesh.userbff.support;

import org.mockito.Mockito;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import reactor.core.publisher.Mono;
import net.hugmesh.userbff.federation.FederationApiClient;

import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

/**
 * Shared {@link FederationApiClient} test double for {@code ProfileService} slice
 * tests: a Mockito mock whose {@code publishVanity}/{@code unpublishVanity} legs
 * always succeed. {@link ProfileService#save} now syncs the caller's federation-api
 * vanity fragment on every username-threaded save (see its class Javadoc); a REAL
 * {@code FederationApiClient} (built with a {@code null} {@code WebClient}, as the
 * pre-existing {@code StubCasdoor} pattern does for {@code CasdoorUserClient}) would
 * NPE the moment a test saves a {@code visibility=public && vanitySubdomainEnabled}
 * profile, so this mock is used instead everywhere {@code ProfileService.class} is
 * {@code @Import}ed into a slice.
 *
 * <p>Tests that specifically assert the sync BEHAVIOUR (owner/displayName forwarding,
 * honest error propagation) use their own dedicated mock — see
 * {@code ProfileServiceFederationSyncTest} — rather than this always-succeeds stub.
 */
@TestConfiguration(proxyBeanMethods = false)
public class StubFederationApiClient {

    @Bean
    public FederationApiClient federationApiClient() {
        FederationApiClient mock = Mockito.mock(FederationApiClient.class);
        when(mock.publishVanity(any(), any())).thenReturn(Mono.just(Map.of()));
        when(mock.unpublishVanity(any())).thenReturn(Mono.empty());
        return mock;
    }
}
