package net.hugmesh.userbff.silence;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import net.hugmesh.userbff.auth.AdminBffInternalClient;

import java.time.Instant;
import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * {@link SelfSilenceExpiryAction} wake-resolution unit test (fully mocked; the companion
 * to the DB-backed {@code SelfSilenceServiceTest}'s sweep coverage). Proves the SCHEDULED
 * (no request JWT) un-hide leg resolves the SAME canonical identity {@code
 * SelfSilenceController} would have resolved at activate-time for the SAME account — the
 * "activate and JWT-less expiry agree" invariant the self-silence identity fix requires —
 * and degrades safely for a row whose stored {@code user_id} is not an admin-bff account
 * id (the documented residual gap for a real-external-JWT-direct row).
 */
class SelfSilenceExpiryActionTest {

    private final SelfSilenceRepository repo = mock(SelfSilenceRepository.class);
    private final SelfSilenceService silence = mock(SelfSilenceService.class);
    private final AdminBffInternalClient adminBff = mock(AdminBffInternalClient.class);
    private final SelfSilenceExpiryAction action = new SelfSilenceExpiryAction(repo, silence, adminBff);

    private static SelfSilence overdue(String userId) {
        return new SelfSilence(userId, Instant.now().minusSeconds(7200),
                Instant.now().minusSeconds(60), null, "afk", Instant.now());
    }

    @Test
    void wake_resolvesCanonicalIdentity_sameFormActivateWouldHaveUsed() {
        // "carol" is an admin-bff account id whose Matrix/Mastodon folds DIVERGE from each
        // other and from the raw account id — exactly the shape SelfSilenceController's
        // claim-first + adminBff-fallback resolves at activate() time (via the SAME
        // AdminBffInternalClient#getAccount call keyed by the JWT subject == account id
        // for a native-login row). The scheduled wake (no request JWT at all) must un-hide
        // under the SAME two canonical values, not the raw "carol" account id.
        when(repo.findOverdueActive(any())).thenReturn(Flux.just(overdue("carol")));
        when(adminBff.getAccount("carol")).thenReturn(Mono.just(
                new AdminBffInternalClient.AccountView("carol", "google", "carol@x.com",
                        true, List.of("user"), "carol-matrix", "carol_mastodon")));
        when(silence.clearHides("carol-matrix", "carol_mastodon")).thenReturn(Mono.empty());
        when(repo.clearSystem("carol")).thenReturn(Mono.just(1L));

        StepVerifier.create(action.sweep()).expectNext(1L).verifyComplete();

        verify(silence).clearHides("carol-matrix", "carol_mastodon");
        // Never the pre-fix behaviour (raw user_id for both legs) once admin-bff resolves.
        verify(silence, never()).clearHides("carol", "carol");
    }

    @Test
    void wake_adminBffUnresolvable_fallsBackToUserIdForBothLegs_lastResortOnly() {
        // Simulates a self-silence row created via a real, externally-issued Casdoor JWT
        // presented directly to the self-silence route (the documented residual gap): the
        // stored user_id is NOT an admin-bff account id, so the lookup 404s and the wake
        // degrades to today's pre-fix behaviour — never breaking the sweep.
        when(repo.findOverdueActive(any())).thenReturn(Flux.just(overdue("mallory")));
        when(adminBff.getAccount("mallory")).thenReturn(Mono.error(
                WebClientResponseException.create(404, "Not Found", HttpHeaders.EMPTY, new byte[0], null)));
        when(silence.clearHides("mallory", "mallory")).thenReturn(Mono.empty());
        when(repo.clearSystem("mallory")).thenReturn(Mono.just(1L));

        StepVerifier.create(action.sweep()).expectNext(1L).verifyComplete();

        verify(silence).clearHides("mallory", "mallory");
    }

    @Test
    void wake_partialResolution_blankMastodonFold_fallsBackForThatLegOnly() {
        // A pre-291 account has a persisted Matrix localpart but no persisted Mastodon fold
        // yet (AccountView.mastodonLocalpart() blank) — the Matrix leg uses the resolved
        // canonical value, the Mastodon leg falls back to user_id for that leg ONLY (a
        // successful-but-partial resolution is not discarded wholesale).
        when(repo.findOverdueActive(any())).thenReturn(Flux.just(overdue("dave")));
        when(adminBff.getAccount("dave")).thenReturn(Mono.just(
                new AdminBffInternalClient.AccountView("dave", "google", "dave@x.com",
                        true, List.of("user"), "dave-matrix")));
        when(silence.clearHides("dave-matrix", "dave")).thenReturn(Mono.empty());
        when(repo.clearSystem("dave")).thenReturn(Mono.just(1L));

        StepVerifier.create(action.sweep()).expectNext(1L).verifyComplete();

        verify(silence).clearHides("dave-matrix", "dave");
    }
}
