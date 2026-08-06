package systems.hugmesh.userbff.client;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import reactor.netty.http.client.HttpClient;
import systems.hugmesh.userbff.federation.FederationHttpClientSsl;

import java.util.Map;

/**
 * Writes a homeserver-token REVOCATION KEY onto the gateway revocation list so the
 * gateway's {@code HomeserverTokenRevocationFilter} denies the credential on its next
 * request (Matrix access tokens are effectively non-expiring → the gateway key is the
 * sole revocation mechanism). This is the WRITE side the gateway's read-only
 * {@code RevocationListService} lacks (see the increment design — the
 * {@code RevocationWriter} primitive).
 *
 * <p>Two key shapes are written here (per the design's per-credential discriminator):
 * <ul>
 *   <li>{@link #revokeConnectedClient} — {@code hs:<platform>:<localpart>:<appId|deviceId>}
 *       (Connected-Apps/Devices revoke: a SINGLE app/device drops, leaving the user's
 *       other sessions untouched);</li>
 *   <li>{@link #revokePersonalClients} — {@code external-client:<localpart>:<platform>}
 *       (external-client-role removal: every {@code kind=personal} token is denied while
 *       the user's {@code kind=brokered} our-UI token keeps working — base our-UI access
 *       is NOT affected).</li>
 * </ul>
 *
 * <p>GATED SEAM (scope-guard), default OFF ({@code gateway.revocation.enabled=false}):
 * until the gateway exposes the revocation-WRITE endpoint, each call is a DOCUMENTED
 * stub that LOGS the key it would write and returns {@code false} (no live call), and
 * NEVER hard-fails — the durable {@code connected_client_audit} stamp / the Casdoor
 * role removal are the source of truth and the gateway key converges when the endpoint
 * ships (eventual consistency ≈ one ≤5s poll tick). When enabled, it POSTs the key to
 * the gateway revocation-write path through the mTLS proxy.
 */
@Component
public class RevocationWriter {

    private static final Logger log = LoggerFactory.getLogger(RevocationWriter.class);

    /** Null unless gateway.revocation.enabled=true — when null every call is a stub. */
    private final WebClient http;
    private final boolean enabled;

    public RevocationWriter(
            FederationHttpClientSsl mtls,
            @Value("${gateway.revocation.enabled:false}") boolean enabled,
            @Value("${gateway.revocation.base-url:${GATEWAY_URL:http://hugmesh-be-gateway.hugmesh-backend.svc.cluster.local:8080}}") String baseUrl) {
        this.enabled = enabled;
        if (enabled) {
            HttpClient httpClient = mtls.customize(HttpClient.create());
            this.http = WebClient.builder()
                    .baseUrl(baseUrl)
                    .clientConnector(new ReactorClientHttpConnector(httpClient))
                    .build();
        } else {
            this.http = null;
        }
    }

    /** Whether the live gateway revocation-write is wired (vs. the documented stub). */
    public boolean enabled() { return enabled; }

    /**
     * Revoke ONE connected app/device: write {@code hs:<platform>:<localpart>:<externalRef>}.
     * Per-credential, so the user's other sessions are unaffected. Best-effort: returns
     * whether a LIVE write ran ({@code false} = stub/disabled); never hard-fails.
     */
    public Mono<Boolean> revokeConnectedClient(String platform, String localpart, String externalRef) {
        String key = "hs:" + platform + ":" + localpart + ":" + externalRef;
        return write(key);
    }

    /**
     * Revoke ALL of the user's PERSONAL clients on a platform without touching base
     * our-UI access: write {@code external-client:<localpart>:<platform>}. The gateway
     * filter checks this key ONLY for {@code kind=personal} tokens, so the user's
     * {@code kind=brokered} our-UI token keeps working. Used when the external-client
     * role is removed (the reconcile/seam). Best-effort, never hard-fails.
     */
    public Mono<Boolean> revokePersonalClients(String platform, String localpart) {
        String key = "external-client:" + localpart + ":" + platform;
        return write(key);
    }

    private Mono<Boolean> write(String key) {
        if (http == null) {
            log.info("[gateway-revocation] (stub) would write revocation key '{}' — live gateway "
                    + "revocation-write disabled (gateway.revocation.enabled=false)", key);
            return Mono.just(false);
        }
        return http.post()
                .uri("/api/gateway/revocations")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(Map.of("key", key))
                .retrieve()
                .toBodilessEntity()
                .thenReturn(true)
                .doOnSuccess(v -> log.info("[gateway-revocation] wrote revocation key '{}'", key))
                .onErrorResume(e -> {
                    log.warn("[gateway-revocation] best-effort write of '{}' failed (audit/role still "
                            + "stand; converges next tick): {}", key, e.toString());
                    return Mono.just(false);
                });
    }
}
