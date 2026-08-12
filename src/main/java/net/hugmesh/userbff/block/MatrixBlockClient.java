package net.hugmesh.userbff.block;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.Map;

/**
 * Pushes a self-block to the in-cluster Matrix homeserver (tuwunel). Base URL is
 * grounded in the hugmesh-generator manifests:
 * {@code http://tuwunel.hugmesh-backend.svc.cluster.local:8008} (env-overridable
 * via {@code MATRIX_URL}).
 *
 * <p>Documented Matrix client-server ignore endpoint (the per-user "ignore"/mute):
 * {@code PUT /_matrix/client/v3/user/{userId}/account_data/m.ignored_user_list}
 * with body {@code {"ignored_users": {"<target>": {}}}}, authorised as the OWNING
 * user (their Matrix access token). A homeserver-side ban is the admin API
 * {@code POST /_synapse/admin/...}; per-user self-block is the ignore list.
 *
 * <p>STUB STATUS: the per-user Matrix access-token acquisition (the BFF would need
 * the caller's Matrix token, brokered via the admin-bff ServiceTokenBroker) is out
 * of scope here, so the live PUT is GATED OFF by default (enabled only when a
 * {@link WebClient} is wired via {@code block.matrix.enabled=true}). The reactive
 * flow is fully wired; when disabled it logs + returns {@code false} (stub) so the
 * durable {@code user_block} row still stands. Validate the ignore-list shape +
 * token brokering before flipping the flag (see README deferrals).
 */
public class MatrixBlockClient implements ExternalBlockClient {

    private static final Logger log = LoggerFactory.getLogger(MatrixBlockClient.class);

    /** Null unless block.matrix.enabled=true — when null every push is a documented stub. */
    private final WebClient http;

    public MatrixBlockClient(WebClient http) {
        this.http = http;
    }

    @Override
    public String platform() { return "matrix"; }

    @Override
    public Mono<Boolean> block(String ownerUserId, String target) {
        if (http == null) {
            log.info("[matrix] (stub) ignore {} on behalf of {} — wired but live Matrix push disabled "
                    + "(block.matrix.enabled=false)", target, ownerUserId);
            return Mono.just(false);
        }
        // Documented shape; the owning user's Matrix access token must be present on
        // the WebClient (brokered) for this to authorise. Best-effort at the caller.
        return http.put()
                .uri("/_matrix/client/v3/user/{userId}/account_data/m.ignored_user_list", ownerUserId)
                .bodyValue(Map.of("ignored_users", Map.of(target, Map.of())))
                .retrieve()
                .toBodilessEntity()
                .thenReturn(true)
                .doOnSuccess(v -> log.info("[matrix] ignored {} for {}", target, ownerUserId));
    }
}
