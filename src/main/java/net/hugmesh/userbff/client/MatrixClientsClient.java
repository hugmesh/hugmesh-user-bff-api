package net.hugmesh.userbff.client;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * CONNECTED APPS & DEVICES seam for the in-cluster Matrix homeserver. Lists the
 * caller's device sessions (Matrix client API {@code GET /_matrix/client/v3/devices})
 * and revokes one ({@code DELETE /_matrix/client/v3/devices/{deviceId}}), reached
 * through the mTLS proxy with the caller's homeserver access token forwarded as the
 * bearer. Base URL is grounded in the hugmesh-generator manifests
 * ({@code MATRIX_URL}, default tuwunel :8008).
 *
 * <p>STUB STATUS (scope-guard): GATED OFF by default (enabled only when a
 * {@link WebClient} is wired via {@code external.matrix.enabled=true}). When disabled
 * the list is empty and the revoke is a logged no-op returning {@code false} (stub) —
 * NEVER a hard-fail. The durable {@code connected_client_audit} row + the
 * per-credential gateway revocation key remain the enforcement.
 */
public class MatrixClientsClient implements HomeserverClientsClient {

    private static final Logger log = LoggerFactory.getLogger(MatrixClientsClient.class);

    /** Null unless external.matrix.enabled=true — when null every call is a stub. */
    private final WebClient http;

    public MatrixClientsClient(WebClient http) {
        this.http = http;
    }

    @Override
    public String platform() { return "matrix"; }

    @Override
    public Flux<ConnectedClient> list(String localpart, String bearer) {
        if (http == null) {
            log.info("[matrix] (stub) list-devices for {} — live tuwunel client-API read disabled "
                    + "(external.matrix.enabled=false)", localpart);
            return Flux.empty();
        }
        // GET /_matrix/client/v3/devices -> {"devices":[{device_id,display_name,...}]}.
        // The bearer is the caller's own Matrix access token (forwarded). Mapping the
        // live response shape to ConnectedClient is pinned when the live read is wired;
        // here the well-formed call path exists + degrades to empty on any error.
        return http.get()
                .uri("/_matrix/client/v3/devices")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + (bearer == null ? "" : bearer))
                .retrieve()
                .bodyToFlux(ConnectedClient.class)
                .onErrorResume(e -> {
                    log.warn("[matrix] best-effort list-devices for {} failed (audit rows still shown): {}",
                            localpart, e.toString());
                    return Flux.empty();
                });
    }

    @Override
    public Mono<Boolean> revoke(String localpart, String externalRef, String bearer) {
        if (http == null) {
            log.info("[matrix] (stub) revoke device {} for {} — live tuwunel client-API delete "
                    + "disabled (external.matrix.enabled=false)", externalRef, localpart);
            return Mono.just(false);
        }
        // DELETE /_matrix/client/v3/devices/{deviceId} invalidates the device's access
        // token at the homeserver (may require UIA in some deployments — pinned later).
        return http.delete()
                .uri("/_matrix/client/v3/devices/{deviceId}", externalRef)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + (bearer == null ? "" : bearer))
                .retrieve()
                .toBodilessEntity()
                .thenReturn(true)
                .doOnSuccess(v -> log.info("[matrix] revoked device {} for {}", externalRef, localpart));
    }
}
