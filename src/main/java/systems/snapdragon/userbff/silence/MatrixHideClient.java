package systems.snapdragon.userbff.silence;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

/**
 * SELF-SILENCE directory hide for the in-cluster Matrix homeserver (tuwunel). Base
 * URL is grounded in the snapdragon-generator manifests
 * {@code http://tuwunel.snapdragon-backend.svc.cluster.local:8008} (env-overridable
 * via {@code MATRIX_URL}).
 *
 * <p>Documented shape: EXCLUDE the user from the public user directory while
 * self-silenced. tuwunel is Conduit-family and has NO Synapse-style REST admin API,
 * so directory exclusion is driven via the admin-room BOT COMMAND path (the same
 * channel a ban's {@code !admin users deactivate} would use) — here a
 * directory-exclude command, explicitly NOT a deactivate (that is a ban). The
 * exact command + admin-room transport are pinned against the deployed server in a
 * paired later phase; the reverse re-includes the user.
 *
 * <p>STUB STATUS (scope-guard): GATED OFF by default (enabled only when a
 * {@link WebClient} is wired via {@code external.matrix.enabled=true}). When disabled
 * it logs + returns {@code false} (stub) and NEVER hard-fails the silence — the
 * durable {@code self_silence} row stands.
 */
public class MatrixHideClient implements HomeserverHideClient {

    private static final Logger log = LoggerFactory.getLogger(MatrixHideClient.class);

    /** Null unless external.matrix.enabled=true — when null every call is a stub. */
    private final WebClient http;

    public MatrixHideClient(WebClient http) {
        this.http = http;
    }

    @Override
    public String platform() { return "matrix"; }

    @Override
    public Mono<Boolean> hide(String localpart) {
        return excludeFromDirectory(localpart, true);
    }

    @Override
    public Mono<Boolean> unhide(String localpart) {
        return excludeFromDirectory(localpart, false);
    }

    private Mono<Boolean> excludeFromDirectory(String localpart, boolean exclude) {
        if (http == null) {
            log.info("[matrix] (stub) exclude-from-directory={} for {} — wired but live tuwunel "
                    + "admin-room push disabled (external.matrix.enabled=false)", exclude, localpart);
            return Mono.just(false);
        }
        // Documented seam: tuwunel (Conduit-family) has no REST admin API, so the live
        // directory-exclude runs via the admin-room bot command channel (pinned later).
        // The HTTP shape below is a PLACEHOLDER for that transport — NEVER a deactivate.
        return http.post()
                .uri("/_snapdragon/admin/directory/{op}/{localpart}", exclude ? "exclude" : "include", localpart)
                .retrieve()
                .toBodilessEntity()
                .thenReturn(true)
                .doOnSuccess(v -> log.info("[matrix] exclude-from-directory={} for {}", exclude, localpart));
    }
}
