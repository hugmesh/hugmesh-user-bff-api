package systems.hugmesh.userbff.silence;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.Map;

/**
 * SELF-SILENCE visibility hide for the in-cluster Mastodon homeserver (akkoma). Base
 * URL is grounded in the hugmesh-generator manifests
 * {@code http://akkoma.snapdragon-backend.svc.cluster.local:4000} (env-overridable
 * via {@code MASTODON_URL}).
 *
 * <p>Documented shape (akkoma / Pleroma): mark the account NOT discoverable —
 * {@code PATCH /api/v1/accounts/update_credentials} with {@code discoverable=false}
 * (and optionally {@code locked=true} if "do not appear" must also gate new
 * follows). This is a pure DISCOVERY flag — it is explicitly NOT
 * {@code .../suspend} / a deactivation (that is a ban). The reverse sets
 * {@code discoverable=true}.
 *
 * <p>STUB STATUS (scope-guard): the live PATCH needs the OWNING user's akkoma token
 * (brokered) and the exact deployed-server flag pinned, so it is GATED OFF by
 * default (enabled only when a {@link WebClient} is wired via
 * {@code external.mastodon.enabled=true}). The reactive flow is fully wired; when
 * disabled it logs + returns {@code false} (stub) and NEVER hard-fails the silence —
 * the durable {@code self_silence} row stands.
 */
public class MastodonHideClient implements HomeserverHideClient {

    private static final Logger log = LoggerFactory.getLogger(MastodonHideClient.class);

    /** Null unless external.mastodon.enabled=true — when null every call is a stub. */
    private final WebClient http;

    public MastodonHideClient(WebClient http) {
        this.http = http;
    }

    @Override
    public String platform() { return "mastodon"; }

    @Override
    public Mono<Boolean> hide(String localpart) {
        return setDiscoverable(localpart, false);
    }

    @Override
    public Mono<Boolean> unhide(String localpart) {
        return setDiscoverable(localpart, true);
    }

    private Mono<Boolean> setDiscoverable(String localpart, boolean discoverable) {
        if (http == null) {
            log.info("[mastodon] (stub) set discoverable={} for {} — wired but live akkoma "
                    + "visibility push disabled (external.mastodon.enabled=false)", discoverable, localpart);
            return Mono.just(false);
        }
        // Documented shape; the owning user's akkoma token must be present on the
        // WebClient (brokered) for this to authorise. discoverable only — NEVER suspend.
        return http.patch()
                .uri("/api/v1/accounts/update_credentials")
                .bodyValue(Map.of("discoverable", discoverable))
                .retrieve()
                .toBodilessEntity()
                .thenReturn(true)
                .doOnSuccess(v -> log.info("[mastodon] set discoverable={} for {}", discoverable, localpart));
    }
}
