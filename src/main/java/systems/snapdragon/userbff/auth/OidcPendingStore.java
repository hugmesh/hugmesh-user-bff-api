package systems.snapdragon.userbff.auth;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Server-side PENDING-AUTHORIZATION store for the OIDC login leg — the small piece of
 * the PKCE/state/nonce flow that has NO home in auth-core (auth-core owns the
 * {@code OidcExchangeClient} code→token exchange; the per-flow correlation state is a
 * BFF concern). It holds, keyed by the opaque {@code state} the BFF handed Casdoor on
 * the authorize redirect, the data the {@link OidcCallbackController} needs to finish
 * the round trip:
 *
 * <ul>
 *   <li>{@code verifier} — the PKCE code-verifier whose S256 challenge went to Casdoor
 *       (only carried when THIS BFF owns PKCE; when login-ui owns PKCE client-side per
 *       #156 the verifier is empty and only {@code state}/{@code nonce} are correlated);</li>
 *   <li>{@code nonce} — the OIDC nonce echoed back in the id_token (replay defence);</li>
 *   <li>{@code redirectUri} — the redirect_uri bound to the authorization request (it
 *       MUST match on the token exchange, so it is pinned per-flow rather than read
 *       from config at callback time).</li>
 * </ul>
 *
 * <p><b>Fail-closed by construction.</b> {@code state} is SINGLE-USE — {@link #consume}
 * removes it atomically, so a replayed callback finds nothing and is rejected. Entries
 * older than {@code app.bff.oidc.pending-ttl} (default 5m) are swept and are also
 * treated as absent on read, so a stale/forged state can never complete a login. This
 * is an in-memory {@link ConcurrentHashMap} (single-replica BFF; a multi-replica
 * deployment would point this at a shared store — out of scope here and not needed
 * while the surface ships dark behind {@code app.bff.oidc.enabled=false}).
 */
@Component
public class OidcPendingStore {

    private static final Logger log = LoggerFactory.getLogger(OidcPendingStore.class);

    /** One pending authorization flow. {@code verifier}/{@code nonce} may be blank when
     *  login-ui owns PKCE client-side (#156) — only the present fields are validated. */
    public record Pending(String verifier, String nonce, String redirectUri, Instant createdAt) {}

    private final Map<String, Pending> pending = new ConcurrentHashMap<>();
    private final Duration ttl;

    public OidcPendingStore(@Value("${app.bff.oidc.pending-ttl:PT5M}") Duration ttl) {
        this.ttl = ttl;
    }

    /** Register a flow under {@code state}; overwrites any prior entry for the same
     *  state (a fresh authorize re-arms it). */
    public void put(String state, String verifier, String nonce, String redirectUri) {
        if (state == null || state.isBlank()) {
            return;
        }
        pending.put(state, new Pending(verifier, nonce, redirectUri, Instant.now()));
    }

    /**
     * Atomically REMOVE and return the flow for {@code state}, or empty when the state
     * is unknown, already consumed (single-use), or expired (TTL). Callers MUST treat
     * empty as a hard rejection (fail-closed) — never proceed with the exchange.
     */
    public Optional<Pending> consume(String state) {
        if (state == null || state.isBlank()) {
            return Optional.empty();
        }
        Pending p = pending.remove(state);
        if (p == null) {
            return Optional.empty();
        }
        if (isExpired(p)) {
            log.debug("[oidc-pending] state expired on consume (age > {})", ttl);
            return Optional.empty();
        }
        return Optional.of(p);
    }

    private boolean isExpired(Pending p) {
        return p.createdAt().plus(ttl).isBefore(Instant.now());
    }

    /** Drop expired flows. Single-replica in-memory store, so a periodic sweep is
     *  enough; {@link #consume} also re-checks the TTL so a never-swept entry can never
     *  complete a login. */
    @Scheduled(fixedDelayString = "${app.bff.oidc.pending-sweep-ms:60000}",
            initialDelayString = "${app.bff.oidc.pending-sweep-ms:60000}")
    void sweep() {
        pending.entrySet().removeIf(e -> isExpired(e.getValue()));
    }

    /** Test/diagnostic: number of live pending flows. */
    int size() {
        return pending.size();
    }
}
