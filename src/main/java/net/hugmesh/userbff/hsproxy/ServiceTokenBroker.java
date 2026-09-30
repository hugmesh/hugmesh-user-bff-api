package net.hugmesh.userbff.hsproxy;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Mono;
import reactor.netty.http.client.HttpClient;
import net.hugmesh.userbff.federation.FederationHttpClientSsl;

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
@SuppressFBWarnings(value = "EI_EXPOSE_REP2",
        justification = "Spring constructor injection: the container owns this singleton collaborator and it is never mutated after construction; a defensive copy of a bean is meaningless (not caller-owned mutable data).")
public class ServiceTokenBroker {

    private static final Logger log = LoggerFactory.getLogger(ServiceTokenBroker.class);

    /**
     * Jackson-2 mapper used to parse homeserver JSON responses OFF the WebFlux
     * codec path (see {@link #postJson}). Boot 4's reactive JSON codec is Jackson 3
     * (tools.jackson), which cannot decode into this Jackson-2 {@link JsonNode}
     * type — so the response is read as a String (always codec-safe) and parsed
     * here. Thread-safe for {@code readTree}.
     */
    private static final ObjectMapper MAPPER = new ObjectMapper();

    /** OAuth scopes for the broker's app + minted user tokens (Mastodon/Akkoma). */
    private static final String MASTODON_SCOPES = "read write follow";

    private final WebClient matrix;
    private final WebClient mastodon;
    private final String svcPassword;
    private final String mastodonEmailDomain;
    private final HsTokenCustody custody;
    private final HsTokenRevocationHashWriter hashWriter;

    /** Lazily-registered doorkeeper app creds ({@code client_id}/{@code client_secret})
     *  — see {@link #ensureMastodonApp}. In-process cache only. */
    private final java.util.concurrent.atomic.AtomicReference<JsonNode> mastodonApp =
            new java.util.concurrent.atomic.AtomicReference<>();

    /**
     * Base URLs default to the per-pod mTLS proxy sidecars (the D6 resolved
     * architecture: the sidecars front the homeservers and pass the Authorization
     * bearer through unchanged). The {@link FederationHttpClientSsl} connector presents
     * this BFF's cluster-CA client identity so the sidecars' {@code ssl_verify_client on}
     * handshake succeeds. Env-overridable.
     */
    @Autowired
    public ServiceTokenBroker(
            FederationHttpClientSsl mtls,
            @Value("${app.hs-token.matrix-url:https://tuwunel-proxy.hugmesh-backend.svc.cluster.local:4443}") String matrixUrl,
            @Value("${app.hs-token.mastodon-url:https://akkoma-proxy.hugmesh-backend.svc.cluster.local:4443}") String mastodonUrl,
            @Value("${app.hs-token.svc-password}") String svcPassword,
            @Value("${app.hs-token.mastodon-email-domain:}") String mastodonEmailDomain,
            HsTokenCustody custody,
            HsTokenRevocationHashWriter hashWriter) {
        HttpClient httpClient = mtls.customize(HttpClient.create());
        ReactorClientHttpConnector connector = new ReactorClientHttpConnector(httpClient);
        this.matrix = WebClient.builder().baseUrl(matrixUrl).clientConnector(connector).build();
        // Plain-HTTP homeserver base (the compose stack talks to mastodon-web:3000
        // directly, no TLS sidecar): assert the edge protocol so mainline Mastodon's
        // force_ssl doesn't 308 every API call (its /health is exempt, so the service
        // LOOKS fine while every real call bounces). The cluster's akkoma-proxy leg is
        // https, so the header is never added there — the sidecar owns proto metadata.
        WebClient.Builder mastodonBuilder = WebClient.builder()
                .baseUrl(mastodonUrl).clientConnector(connector);
        if (mastodonUrl != null && mastodonUrl.startsWith("http://")) {
            mastodonBuilder.defaultHeader("X-Forwarded-Proto", "https");
        }
        this.mastodon = mastodonBuilder.build();
        this.svcPassword = svcPassword;
        this.mastodonEmailDomain = mastodonEmailDomain;
        this.custody = custody;
        this.hashWriter = hashWriter;
    }

    /**
     * Test seam — inject pre-built {@link WebClient}s (e.g. backed by a stub
     * exchange) so the JSON decode path can be exercised without a live homeserver
     * or the mTLS connector. Production uses the {@code @Autowired} constructor above.
     */
    ServiceTokenBroker(WebClient matrix, WebClient mastodon, String svcPassword,
                       HsTokenCustody custody, HsTokenRevocationHashWriter hashWriter) {
        this(matrix, mastodon, svcPassword, "e2e.local", custody, hashWriter);
    }

    /** Test seam with an explicit mastodon email domain. */
    ServiceTokenBroker(WebClient matrix, WebClient mastodon, String svcPassword,
                       String mastodonEmailDomain,
                       HsTokenCustody custody, HsTokenRevocationHashWriter hashWriter) {
        this.matrix = matrix;
        this.mastodon = mastodon;
        this.mastodonEmailDomain = mastodonEmailDomain;
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
     * Fail-closed guard for an unprovisioned service password. The broker is an
     * unconditional {@code @Service} (the always-present proxy controllers inject it),
     * so {@code app.hs-token.svc-password} now carries an EMPTY default — a deploy that
     * leaves it unset boots cleanly instead of failing the whole context on an unresolved
     * placeholder. A mint without a password cannot succeed, so we 503 here BEFORE any
     * homeserver call — exactly how an unconfigured custody {@code key} (HsTokenCipher)
     * 503s rather than brokering with an empty/known credential. Returns {@code null}
     * when the password is present (caller proceeds normally).
     */
    private Mono<MintedToken> requireServicePassword() {
        if (svcPassword == null || svcPassword.isBlank()) {
            log.warn("[hs-token-broker] mint refused: app.hs-token.svc-password is unset (fail-closed 503)");
            return Mono.error(new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,
                    "homeserver token brokering unavailable: service password not configured"));
        }
        return null;
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
        Mono<MintedToken> guard = requireServicePassword();
        if (guard != null) {
            return guard;
        }
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
     * Mastodon/Akkoma localparts allow ONLY {@code [a-z0-9_]} (Mastodon rejects the
     * {@code .-=/} the Matrix charset permits with "must contain only letters, numbers
     * and underscores") and are capped at 30 CHARACTERS ("Username is too long
     * (maximum is 30 characters)" — live-verified; a folded 36-char casdoor-UUID handle
     * trips it). Disallowed characters FOLD to {@code '_'} (position-preserving, so
     * {@code a-b} and {@code a.b} stay distinct from {@code ab}); over-long names
     * TRUNCATE to 30 (a UUID keeps 28 significant hex chars ≈ 112 bits — collision-safe).
     */
    public static String mastodonLocalpart(String handle) {
        String base = (handle == null ? "user" : handle).split("@")[0].toLowerCase();
        String cleaned = base.replaceAll("[^a-z0-9_]", "_");
        if (cleaned.length() > 30) {
            cleaned = cleaned.substring(0, 30);
        }
        return cleaned.replaceAll("_", "").isEmpty() ? "user" : cleaned;
    }

    /**
     * Mint (or re-mint) a Mastodon/Akkoma homeserver-native token for
     * {@code ownerSubject} whose handle is {@code localpart} — the REAL OAuth contract
     * (live-verified against mainline Mastodon v4.3; Pleroma/Akkoma implements the same
     * three endpoints):
     *
     * <ol>
     *   <li><b>ensure an OAuth app</b> — {@code POST /api/v1/apps} (unauthenticated),
     *       cached in-process. Doorkeeper refuses BOTH grants below without
     *       {@code client_id}/{@code client_secret}, which is why the previous bare
     *       {@code {grant_type,username,password}} body never worked against any real
     *       server ({@code 401 invalid_client}) — it was ported from the mock-bff;</li>
     *   <li><b>recover</b> — password grant WITH the app creds, {@code username} = the
     *       account EMAIL ({@code <localpart>@<app.hs-token.mastodon-email-domain>};
     *       Mastodon authenticates by email, Pleroma accepts either); succeeds for an
     *       account this broker previously registered (password = svc-password);</li>
     *   <li><b>register</b> — on an empty/invalid grant, {@code client_credentials} →
     *       app token → {@code POST /api/v1/accounts} (username/email/svc-password/
     *       agreement), which returns a USER token directly. Needs the instance's
     *       registrations OPEN ({@code tootctl settings registrations open} on the
     *       compose stack). Mainline Mastodon additionally holds fresh accounts at
     *       403 until email-confirm ({@code tootctl accounts modify --confirm} —
     *       no SMTP on the local stack); Akkoma (the cluster target) requires no
     *       activation. A localpart someone ELSE owns (e.g. a tootctl-seeded account
     *       with a random password) fails BOTH legs → fail-closed, never a takeover.</li>
     * </ol>
     *
     * <p>Fail-closed gates: svc-password unset → 503 (shared guard);
     * {@code app.hs-token.mastodon-email-domain} unset → 503 (the email is load-bearing
     * for both legs, so there is no meaningful degraded mode). On success the token is
     * encrypted + upserted into the custody row AND its hash is written to the gateway
     * registry. Returns the in-process token.
     */
    public Mono<MintedToken> mintMastodon(String ownerSubject, String localpart) {
        Mono<MintedToken> guard = requireServicePassword();
        if (guard != null) {
            return guard;
        }
        if (mastodonEmailDomain == null || mastodonEmailDomain.isBlank()) {
            log.warn("[hs-token-broker] mastodon mint refused: app.hs-token.mastodon-email-domain is unset (fail-closed 503)");
            return Mono.error(new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,
                    "mastodon token brokering unavailable: email domain not configured"));
        }
        String user = mastodonLocalpart(localpart);
        String email = user + "@" + mastodonEmailDomain;
        return ensureMastodonApp()
                .flatMap(app -> mastodonPasswordGrant(app, email)
                        .switchIfEmpty(Mono.defer(() -> mastodonRegister(app, user, email))))
                .flatMap(node -> buildMastodonToken(node, ownerSubject, user));
    }

    /**
     * The OAuth app this broker mints through, created lazily via the unauthenticated
     * {@code POST /api/v1/apps} and cached in-process (a lost race just creates one
     * extra doorkeeper app row — harmless). Never persisted; a restart re-registers.
     */
    private Mono<JsonNode> ensureMastodonApp() {
        JsonNode cached = mastodonApp.get();
        if (cached != null) {
            return Mono.just(cached);
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("client_name", "hugmesh-user-bff-broker");
        body.put("redirect_uris", "urn:ietf:wg:oauth:2.0:oob");
        body.put("scopes", MASTODON_SCOPES);
        return postJson(mastodon, "/api/v1/apps", body)
                .flatMap(node -> {
                    if (!node.hasNonNull("client_id") || !node.hasNonNull("client_secret")) {
                        return Mono.error(new IllegalStateException(
                                "mastodon mint: app registration returned no client credentials"));
                    }
                    mastodonApp.compareAndSet(null, node);
                    return Mono.just(mastodonApp.get());
                });
    }

    /** Password-grant recover leg: yields the token node, or EMPTY when the grant is
     *  refused (unknown account / wrong password — the cue to try registration). */
    private Mono<JsonNode> mastodonPasswordGrant(JsonNode app, String email) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("grant_type", "password");
        body.put("username", email);
        body.put("password", svcPassword);
        body.put("client_id", app.path("client_id").asText());
        body.put("client_secret", app.path("client_secret").asText());
        body.put("scope", MASTODON_SCOPES);
        return postJson(mastodon, "/oauth/token", body)
                .filter(node -> node.hasNonNull("access_token"));
    }

    /** Register leg: client_credentials app token → {@code POST /api/v1/accounts},
     *  which returns a USER token directly on success. */
    private Mono<JsonNode> mastodonRegister(JsonNode app, String user, String email) {
        Map<String, Object> tokenBody = new LinkedHashMap<>();
        tokenBody.put("grant_type", "client_credentials");
        tokenBody.put("client_id", app.path("client_id").asText());
        tokenBody.put("client_secret", app.path("client_secret").asText());
        tokenBody.put("scope", MASTODON_SCOPES);
        return postJson(mastodon, "/oauth/token", tokenBody)
                .flatMap(tok -> mastodonCreateAccount(tok, user, email));
    }

    /** The {@link #mastodonRegister} leg after the app token: {@code POST /api/v1/accounts}. */
    private Mono<JsonNode> mastodonCreateAccount(JsonNode tok, String user, String email) {
        if (!tok.hasNonNull("access_token")) {
            return Mono.error(new IllegalStateException(
                    "mastodon mint: client_credentials grant returned no app token"));
        }
        Map<String, Object> reg = new LinkedHashMap<>();
        reg.put("username", user);
        reg.put("email", email);
        reg.put("password", svcPassword);
        reg.put("agreement", true);
        reg.put("locale", "en");
        return mastodon.post().uri("/api/v1/accounts")
                .contentType(MediaType.APPLICATION_JSON)
                .header("Authorization", "Bearer " + tok.path("access_token").asText())
                .bodyValue(reg)
                .exchangeToMono(resp -> resp.statusCode().is5xxServerError()
                        ? resp.createException().flatMap(e -> Mono.<String>error(e))
                        : resp.bodyToMono(String.class))
                .flatMap(ServiceTokenBroker::parseJson)
                .switchIfEmpty(Mono.fromSupplier(JsonNodeFactory.instance::objectNode));
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
                // The homeserver speaks PROTOCOL through 4xx bodies: Synapse's UIA
                // register flow returns the stage-2 `session` in a 401 (which
                // resolveMatrixToken consumes), a taken localpart is a 400
                // M_USER_IN_USE the register→login fallback must fall through on,
                // and a registration-disabled 403 likewise falls through to the
                // password login. retrieve() throws on ANY 4xx and killed the mint
                // at stage 1 — the UIA leg could never complete. Parse 2xx/4xx
                // bodies; only 5xx (homeserver-side failure, no protocol meaning)
                // stays an error. Downstream stays fail-closed either way: a 4xx
                // body without access_token/session ends in the explicit
                // "no access_token" error, never a minted row.
                // Boot 4's reactive JSON codec is Jackson 3 (tools.jackson) and
                // cannot decode into this Jackson-2 JsonNode; read the body as a
                // String (always codec-safe) and parse it with the Jackson-2 mapper.
                .exchangeToMono(resp -> resp.statusCode().is5xxServerError()
                        ? resp.createException().flatMap(e -> Mono.<String>error(e))
                        : resp.bodyToMono(String.class))
                .flatMap(ServiceTokenBroker::parseJson)
                .switchIfEmpty(Mono.fromSupplier(JsonNodeFactory.instance::objectNode));
    }

    /**
     * Parse a homeserver JSON body with the Jackson-2 {@link #MAPPER}. A blank or
     * empty body yields an empty {@link Mono} so the caller's {@code switchIfEmpty}
     * supplies an empty object node (preserving the prior empty-response behaviour).
     */
    private static Mono<JsonNode> parseJson(String json) {
        if (json == null || json.isBlank()) {
            return Mono.empty();
        }
        try {
            return Mono.just(MAPPER.readTree(json));
        } catch (JsonProcessingException e) {
            return Mono.error(new IllegalStateException(
                    "broker: invalid JSON response from homeserver", e));
        }
    }
}
