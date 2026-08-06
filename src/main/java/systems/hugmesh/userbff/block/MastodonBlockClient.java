package systems.hugmesh.userbff.block;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

/**
 * Pushes a self-block to the in-cluster fediverse server (Akkoma — Mastodon-API
 * compatible). Base URL is grounded in the hugmesh-generator manifests:
 * {@code http://akkoma.hugmesh-backend.svc.cluster.local:4000} (env-overridable
 * via {@code MASTODON_URL}).
 *
 * <p>Documented Mastodon-API block endpoint (the per-user account block):
 * {@code POST /api/v1/accounts/{id}/block}, authorised as the OWNING user (their
 * OAuth access token). The account {@code id} is resolved from the target handle
 * via {@code GET /api/v1/accounts/lookup?acct=<target>} first.
 *
 * <p>STUB STATUS: the per-user Mastodon/Akkoma OAuth token acquisition is out of
 * scope here, so the live POST is GATED OFF by default (enabled only when a
 * {@link WebClient} is wired via {@code block.mastodon.enabled=true}). The reactive
 * flow is fully wired; when disabled it logs + returns {@code false} (stub) so the
 * durable {@code user_block} row still stands. Validate the lookup+block shape +
 * token brokering before flipping the flag (see README deferrals).
 */
public class MastodonBlockClient implements ExternalBlockClient {

    private static final Logger log = LoggerFactory.getLogger(MastodonBlockClient.class);

    /** Null unless block.mastodon.enabled=true — when null every push is a documented stub. */
    private final WebClient http;

    public MastodonBlockClient(WebClient http) {
        this.http = http;
    }

    @Override
    public String platform() { return "mastodon"; }

    @Override
    public Mono<Boolean> block(String ownerUserId, String target) {
        if (http == null) {
            log.info("[mastodon] (stub) block {} on behalf of {} — wired but live Mastodon push disabled "
                    + "(block.mastodon.enabled=false)", target, ownerUserId);
            return Mono.just(false);
        }
        // Resolve the target handle to an account id, then POST the block. The
        // owning user's OAuth token must be on the WebClient (brokered) to authorise.
        return http.get()
                .uri(uri -> uri.path("/api/v1/accounts/lookup").queryParam("acct", target).build())
                .retrieve()
                .bodyToMono(AccountLookup.class)
                .flatMap(acct -> http.post()
                        .uri("/api/v1/accounts/{id}/block", acct.id())
                        .retrieve()
                        .toBodilessEntity()
                        .thenReturn(true))
                .doOnSuccess(v -> log.info("[mastodon] blocked {} for {}", target, ownerUserId));
    }

    /** Minimal projection of the Mastodon account-lookup response. */
    record AccountLookup(String id) {}
}
