package net.hugmesh.userbff.client;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * CONNECTED APPS & DEVICES seam for the in-cluster Mastodon homeserver (akkoma).
 * Lists the caller's authorized OAuth applications and revokes one (akkoma/Mastodon
 * OAuth {@code POST /oauth/revoke}), reached through the mTLS proxy with the caller's
 * homeserver token forwarded. Base URL is grounded in the hugmesh-generator
 * manifests ({@code MASTODON_URL}, default akkoma :4000).
 *
 * <p>STUB STATUS (scope-guard): GATED OFF by default (enabled only when a
 * {@link WebClient} is wired via {@code external.mastodon.enabled=true}). When disabled
 * the list is empty and the revoke is a logged no-op returning {@code false} (stub) —
 * NEVER a hard-fail. The durable {@code connected_client_audit} row + the
 * per-credential gateway revocation key remain the enforcement.
 */
public class MastodonClientsClient implements HomeserverClientsClient {

    private static final Logger log = LoggerFactory.getLogger(MastodonClientsClient.class);

    /** Null unless external.mastodon.enabled=true — when null every call is a stub. */
    private final WebClient http;

    public MastodonClientsClient(WebClient http) {
        this.http = http;
    }

    @Override
    public String platform() { return "mastodon"; }

    @Override
    public Flux<ConnectedClient> list(String localpart, String bearer) {
        if (http == null) {
            log.info("[mastodon] (stub) list-apps for {} — live akkoma OAuth-app read disabled "
                    + "(external.mastodon.enabled=false)", localpart);
            return Flux.empty();
        }
        // The authorized-apps read shape is pinned when the live read is wired; here the
        // well-formed call path exists + degrades to empty on any error.
        return http.get()
                .uri("/api/v1/apps/verify_credentials")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + (bearer == null ? "" : bearer))
                .retrieve()
                .bodyToFlux(ConnectedClient.class)
                .onErrorResume(e -> {
                    log.warn("[mastodon] best-effort list-apps for {} failed (audit rows still shown): {}",
                            localpart, e.toString());
                    return Flux.empty();
                });
    }

    @Override
    public Mono<Boolean> revoke(String localpart, String externalRef, String bearer) {
        if (http == null) {
            log.info("[mastodon] (stub) revoke app {} for {} — live akkoma OAuth-revoke disabled "
                    + "(external.mastodon.enabled=false)", externalRef, localpart);
            return Mono.just(false);
        }
        // POST /oauth/revoke invalidates the app's token at the homeserver.
        return http.post()
                .uri("/oauth/revoke")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + (bearer == null ? "" : bearer))
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .bodyValue("token=" + (externalRef == null ? "" : externalRef))
                .retrieve()
                .toBodilessEntity()
                .thenReturn(true)
                .doOnSuccess(v -> log.info("[mastodon] revoked app {} for {}", externalRef, localpart));
    }
}
