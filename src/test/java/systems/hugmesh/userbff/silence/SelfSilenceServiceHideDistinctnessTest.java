package systems.hugmesh.userbff.silence;

import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import systems.hugmesh.userbff.federation.FederationApiClient;

import java.time.Instant;
import java.util.List;

import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * PLATFORM-DISTINCTNESS unit test for {@link SelfSilenceService#applyHides}/{@link
 * SelfSilenceService#clearHides} — with the two {@link HomeserverHideClient}s (and
 * {@link FederationApiClient}) fully mocked (no DB, no Liquibase; the widened-signature
 * companion to {@code SelfSilenceServiceTest}'s DB-backed slice).
 *
 * <p>Since #118 split the Matrix and Mastodon canonical folds, the SAME account can
 * legitimately have a DIFFERENT localpart on each platform. Proves each platform's
 * {@link HomeserverHideClient} is called with ITS OWN localpart — never the other
 * platform's — closing the sibling bug the self-silence identity fix found while reading
 * this class: {@code applyHides}/{@code clearHides} used to take ONE localpart and pass
 * it to BOTH the {@code "mastodon"} and {@code "matrix"} clients.
 */
class SelfSilenceServiceHideDistinctnessTest {

    private static final String MATRIX_LP = "alice-matrix";
    private static final String MASTODON_LP = "alice_mastodon";

    private final SelfSilenceRepository repo = mock(SelfSilenceRepository.class);
    private final FederationApiClient federation = mock(FederationApiClient.class);
    private final HomeserverHideClient matrixClient = mock(HomeserverHideClient.class);
    private final HomeserverHideClient mastodonClient = mock(HomeserverHideClient.class);

    private SelfSilenceService service() {
        when(matrixClient.platform()).thenReturn("matrix");
        when(mastodonClient.platform()).thenReturn("mastodon");
        // federationHideEnabled=false: only the two homeserver legs are under test here.
        return new SelfSilenceService(repo, federation, List.of(matrixClient, mastodonClient), false);
    }

    @Test
    void applyHides_callsEachPlatformClient_withItsOwnLocalpart_neverTheOther() {
        when(matrixClient.hide(MATRIX_LP)).thenReturn(Mono.just(true));
        when(mastodonClient.hide(MASTODON_LP)).thenReturn(Mono.just(true));

        StepVerifier.create(service().applyHides(MATRIX_LP, MASTODON_LP)).verifyComplete();

        verify(matrixClient).hide(MATRIX_LP);
        verify(mastodonClient).hide(MASTODON_LP);
        // The exact cross-wiring bug this fix closes: neither client is ever called with
        // the OTHER platform's localpart.
        verify(matrixClient, never()).hide(MASTODON_LP);
        verify(mastodonClient, never()).hide(MATRIX_LP);
    }

    @Test
    void clearHides_callsEachPlatformClient_withItsOwnLocalpart_neverTheOther() {
        when(matrixClient.unhide(MATRIX_LP)).thenReturn(Mono.just(true));
        when(mastodonClient.unhide(MASTODON_LP)).thenReturn(Mono.just(true));

        StepVerifier.create(service().clearHides(MATRIX_LP, MASTODON_LP)).verifyComplete();

        verify(matrixClient).unhide(MATRIX_LP);
        verify(mastodonClient).unhide(MASTODON_LP);
        verify(matrixClient, never()).unhide(MASTODON_LP);
        verify(mastodonClient, never()).unhide(MATRIX_LP);
    }

    @Test
    void backCompatSingleLocalpartOverload_stillAppliesSameValueToBothPlatforms() {
        // The kept back-compat 1-localpart overloads (pre-#118-split callers/tests, e.g.
        // SelfSilenceServiceTest) must still delegate (lp, lp) — proving no silent
        // behaviour change for callers that have not been migrated to the two-localpart form.
        String shared = "shared-lp";
        Instant expiry = Instant.now().plusSeconds(3600);
        when(matrixClient.hide(shared)).thenReturn(Mono.just(true));
        when(mastodonClient.hide(shared)).thenReturn(Mono.just(true));
        when(repo.activate(eq("bob"), eq(expiry), eq("afk"), eq("brandx")))
                .thenReturn(Mono.just(new SelfSilence("bob", Instant.now(), expiry, null, "afk", Instant.now())));

        StepVerifier.create(service().activate("bob", shared, expiry, "afk", "brandx"))
                .expectNextCount(1)
                .verifyComplete();

        verify(matrixClient).hide(shared);
        verify(mastodonClient).hide(shared);
    }
}
