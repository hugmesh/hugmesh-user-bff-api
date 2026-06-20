package systems.snapdragon.userbff.auth;

import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for the server-side {@link OidcPendingStore} — the PKCE/state/nonce
 * correlation store. Proves the fail-closed invariants: state is SINGLE-USE, expired
 * entries are treated as absent, unknown/blank states are rejected, and the
 * verifier/nonce/redirectUri round-trip intact.
 */
class OidcPendingStoreTest {

    @Test
    void roundTrip_returnsVerifierNonceAndRedirect() {
        OidcPendingStore store = new OidcPendingStore(Duration.ofMinutes(5));
        store.put("state-1", "verifier-abc", "nonce-xyz", "https://snapdragon.systems/login/callback");

        Optional<OidcPendingStore.Pending> got = store.consume("state-1");

        assertThat(got).isPresent();
        assertThat(got.get().verifier()).isEqualTo("verifier-abc");
        assertThat(got.get().nonce()).isEqualTo("nonce-xyz");
        assertThat(got.get().redirectUri()).isEqualTo("https://snapdragon.systems/login/callback");
    }

    @Test
    void state_isSingleUse_secondConsumeIsEmpty() {
        OidcPendingStore store = new OidcPendingStore(Duration.ofMinutes(5));
        store.put("state-1", "v", "n", "r");

        assertThat(store.consume("state-1")).isPresent();
        // A replayed callback with the same state finds nothing — fail closed.
        assertThat(store.consume("state-1")).isEmpty();
    }

    @Test
    void unknownState_isRejected() {
        OidcPendingStore store = new OidcPendingStore(Duration.ofMinutes(5));
        assertThat(store.consume("never-registered")).isEmpty();
    }

    @Test
    void blankOrNullState_isRejected() {
        OidcPendingStore store = new OidcPendingStore(Duration.ofMinutes(5));
        store.put("", "v", "n", "r");          // blank put is a no-op
        store.put(null, "v", "n", "r");        // null put is a no-op
        assertThat(store.consume("")).isEmpty();
        assertThat(store.consume(null)).isEmpty();
        assertThat(store.size()).isZero();
    }

    @Test
    void expiredState_isTreatedAsAbsentOnConsume() {
        // Zero TTL ⇒ every entry is already expired the instant after it is stored.
        OidcPendingStore store = new OidcPendingStore(Duration.ZERO);
        store.put("state-1", "v", "n", "r");
        assertThat(store.consume("state-1")).isEmpty();
    }

    @Test
    void sweep_dropsExpiredEntries() {
        OidcPendingStore store = new OidcPendingStore(Duration.ZERO);
        store.put("state-1", "v", "n", "r");
        store.put("state-2", "v", "n", "r");
        assertThat(store.size()).isEqualTo(2);

        store.sweep();

        assertThat(store.size()).isZero();
    }
}
