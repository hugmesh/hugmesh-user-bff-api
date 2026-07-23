package systems.hugmesh.userbff.hsproxy;

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

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Records the {@code token-hash -> {localpart, platform, kind}} row at homeserver token
 * (re-)MINT time so the gateway's {@code HomeserverTokenRevocationFilter} can later
 * resolve an opaque homeserver bearer back to a localpart and deny it when revoked
 * (Matrix access tokens are effectively non-expiring → the gateway key is the sole
 * revocation mechanism).
 *
 * <p>This is the user-bff (D6, {@code kind=brokered}) write side — the port of the
 * admin-bff {@code HsTokenRegistry} intent. admin-bff writes the row to Cassandra
 * directly; user-bff has NO Cassandra wiring, so it REUSES the existing mTLS WebClient
 * path (same {@link FederationHttpClientSsl} client-cert presentation as
 * {@code RevocationWriter}) and POSTs the SHA-256 hash to the gateway's mint-record
 * endpoint. The gateway does the SAME SHA-256 on the incoming bearer so the lookup key
 * matches.
 *
 * <p>GATED, DEFAULT OFF ({@code app.hs-token.registry.enabled=false}): until the gateway
 * exposes the mint-record endpoint, each call is a DOCUMENTED stub that LOGS the
 * hash-prefix it would write and returns without a live call. It NEVER hard-fails — a
 * recording failure is swallowed so the mint still succeeds (the custody row + the
 * decrypted token are the source of truth; the gateway hash converges next tick). The
 * raw token is NEVER logged (only its hash prefix).
 */
@Component
public class HsTokenRevocationHashWriter {

    private static final Logger log = LoggerFactory.getLogger(HsTokenRevocationHashWriter.class);

    /** Brokered (our-UI) token discriminator — mirrors admin-bff HsTokenRegistry. */
    public static final String KIND_BROKERED = "brokered";

    /** Null unless app.hs-token.registry.enabled=true — when null every call is a stub. */
    private final WebClient http;
    private final boolean enabled;

    public HsTokenRevocationHashWriter(
            FederationHttpClientSsl mtls,
            @Value("${app.hs-token.registry.enabled:false}") boolean enabled,
            @Value("${app.hs-token.registry.base-url:${GATEWAY_URL:http://snapdragon-gateway.snapdragon-backend.svc.cluster.local:8080}}") String baseUrl) {
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

    public boolean enabled() {
        return enabled;
    }

    /**
     * Record a freshly-(re-)minted brokered homeserver token's hash. Best-effort: a
     * recording failure is swallowed so the mint still returns the token to the caller.
     *
     * @param accessToken the opaque homeserver access token (its SHA-256 hex is the key)
     * @param localpart   the homeserver localpart the token authenticates
     * @param platform    {@code matrix} or {@code mastodon}
     */
    public Mono<Void> recordBrokered(String accessToken, String localpart, String platform) {
        if (accessToken == null || accessToken.isBlank() || localpart == null || localpart.isBlank()) {
            return Mono.empty();
        }
        String tokenHash = sha256Hex(accessToken);
        if (http == null) {
            log.info("[hs-tokens] (stub) would record mint hash {}... platform={} localpart={} "
                    + "(live registry disabled: app.hs-token.registry.enabled=false)",
                    tokenHash.substring(0, 8), platform, localpart);
            return Mono.empty();
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("tokenHash", tokenHash);
        body.put("localpart", localpart);
        body.put("platform", platform);
        body.put("kind", KIND_BROKERED);
        body.put("mintedAt", Instant.now().toString());
        return http.post()
                .uri("/api/gateway/hs-tokens")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(body)
                .retrieve()
                .toBodilessEntity()
                .then()
                .doOnSuccess(v -> log.debug("[hs-tokens] recorded mint hash {}... platform={} localpart={}",
                        tokenHash.substring(0, 8), platform, localpart))
                .onErrorResume(e -> {
                    log.warn("[hs-tokens] best-effort mint-hash record for {}:{} failed "
                            + "(token still issued; converges next tick): {}",
                            platform, localpart, e.toString());
                    return Mono.empty();
                });
    }

    /** SHA-256 hex (mirrors the gateway HomeserverTokenRevocationFilter + admin-bff). */
    static String sha256Hex(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(digest.length * 2);
            for (byte b : digest) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 is guaranteed present in every Java runtime.
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }
}
