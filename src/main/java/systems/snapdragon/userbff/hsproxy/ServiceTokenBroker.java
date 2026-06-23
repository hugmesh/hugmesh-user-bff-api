package systems.snapdragon.userbff.hsproxy;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import reactor.netty.http.client.HttpClient;
import systems.snapdragon.userbff.federation.FederationHttpClientSsl;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Mints (or recovers) REAL Matrix (tuwunel) and Mastodon (Akkoma) homeserver-NATIVE
 * access tokens server-side (reactive), so the user-ui never holds homeserver
 * credentials — the BFF mints them against the real services and holds them in the
 * custody store. The reactive port of the admin-bff {@code ServiceTokenBroker}
 * register-then-login (Matrix) / password-grant (Mastodon) brokering.
 *
 * <p>D6 difference from admin-bff: the mint goes through the per-pod mTLS proxy sidecars
 * ({@code tuwunel-proxy:4443} / {@code akkoma-proxy:4443}, {@code ssl_verify_client on})
 * over the existing {@link FederationHttpClientSsl} client-cert presentation — NOT the
 * direct homeserver service — so brokered traffic is gated by the gateway revocation
 * filter. On a successful mint the token is encrypted + UPSERTed into the
 * {@link HsTokenCustody custody store} AND its SHA-256 hash is written to the gateway via
 * {@link HsTokenRevocationHashWriter} (so the gateway's
 * {@code HomeserverTokenRevocationFilter} keeps working).
 *
 * <p>The mint result ({@link MintedToken}) is IN-PROCESS ONLY — never serialised to a
 * client. The proxy uses it to inject the homeserver-native bearer and nothing more.
 */
@Service
public class ServiceTokenBroker {

    private static final Logger log = LoggerFactory.getLogger(ServiceTokenBroker.class);

    private final WebClient matrix;
    private final WebClient mastodon;
    private final String svcPassword;
    private final HsTokenCustody custody;
    private final HsTokenRevocationHashWriter hashWriter;

    /**
     * Base URLs default to the per-pod mTLS proxy sidecars (the D6 resolved
     * architecture: the sidecars front the homeservers and pass the Authorization
     * bearer through unchanged). The {@link FederationHttpClientSsl} connector presents
     * this BFF's cluster-CA client identity so the sidecars' {@code ssl_verify_client on}
     * handshake succeeds. Env-overridable.
     */
    public ServiceTokenBroker(
            FederationHttpClientSsl mtls,
            @Value("${app.hs-token.matrix-url:https://tuwunel-proxy.snapdragon-backend.svc.cluster.local:4443}") String matrixUrl,
            @Value("${app.hs-token.mastodon-url:https://akkoma-proxy.snapdragon-backend.svc.cluster.local:4443}") String mastodonUrl,
            @Value("${app.hs-token.svc-password:snapdragon-svc-pw}") String svcPassword,
            HsTokenCustody custody,
            HsTokenRevocationHashWriter hashWriter) {
        HttpClient httpClient = mtls.customize(HttpClient.create());
        ReactorClientHttpConnector connector = new ReactorClientHttpConnector(httpClient);
        this.matrix = WebClient.builder().baseUrl(matrixUrl).clientConnector(connector).build();
        this.mastodon = WebClient.builder().baseUrl(mastodonUrl).clientConnector(connector).build();
        this.svcPassword = svcPassword;
        this.custody = custody;
        this.hashWriter = hashWriter;
    }

    /** Sanitise a handle into a homeserver localpart (mirrors admin-bff matrixUser). */
    public static String localpart(String handle) {
        String base = (handle == null ? "user" : handle).split("@")[0].toLowerCase();
        String cleaned = base.replaceAll("[^a-z0-9._=/-]", "");
        return cleaned.isEmpty() ? "user" : cleaned;
    }

    /**
     * Mint (or re-mint) a Matrix homeserver-native token for {@code ownerSubject} whose
     * homeserver handle is {@code localpart}: register, else password-login. On success
     * the token is encrypted + upserted into the owner's custody row AND its hash is
     * written to the gateway registry. Returns the in-process {@link MintedToken}.
     *
     * <p>SUSPENSION GUARD: user-bff has no local {@code SuspensionService} (that lives in
     * admin-bff, which owns a SEPARATE Postgres with mutual NetworkPolicy denial). The
     * source-of-truth suspension check is the gateway's {@code access_suspension} /
     * revocation filter — a suspended localpart's token is denied at the gateway on its
     * next request even though it minted here. This is a DOCUMENTED seam, not a silent
     * gap: re-introduce a local guard if user-bff ever gains a suspension mirror.
     */
    public Mono<MintedToken> mintMatrix(String ownerSubject, String localpart) {
        String user = localpart(localpart);
        // Register (or fall through to login if already registered), then persist the token.
        return matrixRegister(user, null)
                .flatMap(reg -> resolveMatrixToken(reg, user))
                .map(node -> new MintedToken(node.path("access_token").asText(), null, null, user))
                .flatMap(token -> persist(ownerSubject, HsServiceTokenRow.PLATFORM_MATRIX, token));
    }

    /** Stage-2 register (dummy UIA) or password-login if the account already exists. */
    private Mono<JsonNode> resolveMatrixToken(JsonNode reg, String user) {
        if (reg.hasNonNull("access_token")) {
            // Register succeeded in one step — token is already in the response.
            return Mono.just(reg);
        }
        String session = reg.path("session").asText(null);
        Mono<JsonNode> stage2 = (session != null)
                ? matrixRegister(user, Map.of("type", "m.login.dummy", "session", session))
                : Mono.empty();
        // Already registered → password login.
        return stage2.filter(r -> r.hasNonNull("access_token"))
                .switchIfEmpty(matrixLogin(user).flatMap(login -> login.hasNonNull("access_token")
                        ? Mono.just(login)
                        : Mono.error(new IllegalStateException("matrix mint: no access_token"))));
    }

    /**
     * Mint (or re-mint) a Mastodon homeserver-native token via the OAuth password grant
     * for {@code ownerSubject} whose handle is {@code localpart}. On success the token
     * (+ refresh + expiry when present) is encrypted + upserted into the custody row AND
     * its hash is written to the gateway registry. Returns the in-process token.
     */
    public Mono<MintedToken> mintMastodon(String ownerSubject, String localpart) {
        String user = localpart(localpart);
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("grant_type", "password");
        body.put("username", user);
        body.put("password", svcPassword);
        // Post the password grant and persist the returned token into the custody store.
        return postJson(mastodon, "/oauth/token", body)
                .flatMap(node -> buildMastodonToken(node, ownerSubject, user));
    }

    /** Extract access/refresh/expiry from the Mastodon OAuth response and persist the token. */
    private Mono<MintedToken> buildMastodonToken(JsonNode node, String ownerSubject, String user) {
        if (!node.hasNonNull("access_token")) {
            return Mono.error(new IllegalStateException("mastodon mint: no access_token"));
        }
        String access = node.path("access_token").asText();
        String refresh = node.hasNonNull("refresh_token") ? node.path("refresh_token").asText() : null;
        Instant expiresAt = node.hasNonNull("expires_in")
                ? Instant.now().plus(node.path("expires_in").asLong(), ChronoUnit.SECONDS)
                : null;
        return persist(ownerSubject, HsServiceTokenRow.PLATFORM_MASTODON,
                new MintedToken(access, refresh, expiresAt, user));
    }

    /** Encrypt + upsert the custody row AND write the gateway revocation hash, then
     *  return the in-process token. The hash write is best-effort (never blocks the
     *  mint); the custody upsert is authoritative (it must succeed). */
    private Mono<MintedToken> persist(String ownerSubject, String platform, MintedToken token) {
        return custody.upsert(ownerSubject, platform, token.accessToken(), token.refreshToken(),
                        token.expiresAt(), token.localpart())
                .then(hashWriter.recordBrokered(token.accessToken(), token.localpart(), platform))
                .thenReturn(token)
                .doOnSuccess(t -> log.debug("[broker] minted {} token for owner={} localpart={}",
                        platform, ownerSubject, token.localpart()));
    }

    // ── Matrix helpers ────────────────────────────────────────────────
    private Mono<JsonNode> matrixRegister(String username, Map<String, Object> auth) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("username", username);
        body.put("password", svcPassword);
        if (auth != null) {
            body.put("auth", auth);
        }
        return postJson(matrix, "/_matrix/client/v3/register", body);
    }

    private Mono<JsonNode> matrixLogin(String username) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("type", "m.login.password");
        body.put("identifier", Map.of("type", "m.id.user", "user", username));
        body.put("password", svcPassword);
        return postJson(matrix, "/_matrix/client/v3/login", body);
    }

    private Mono<JsonNode> postJson(WebClient client, String path, Object body) {
        return client.post().uri(path)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(body)
                .retrieve()
                .bodyToMono(JsonNode.class)
                .switchIfEmpty(Mono.fromSupplier(JsonNodeFactory.instance::objectNode));
    }
}
