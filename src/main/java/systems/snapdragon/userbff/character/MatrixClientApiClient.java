package systems.snapdragon.userbff.character;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.Collections;
import java.util.Map;

/**
 * Generic per-USER Matrix client-server ACCOUNT-DATA client (GET + PUT) for the
 * MSC2545 sticker-pack registration. Base URL is the in-cluster Matrix homeserver
 * (tuwunel) {@code http://tuwunel.snapdragon-backend.svc.cluster.local:8008} —
 * env-overridable via {@code MATRIX_URL} — the DIRECT C-S endpoint (NOT the mTLS
 * sidecar; mirrors {@link systems.snapdragon.userbff.block.MatrixBlockClient}).
 *
 * <p>Documented Matrix client-server account-data endpoints, authorised as the OWNING
 * user (their homeserver-native access token, passed PER CALL — never a default header):
 * <ul>
 *   <li>{@code GET  /_matrix/client/v3/user/{userId}/account_data/{type}} — read the
 *       current account-data object for a type (a 404 when none is set yet);</li>
 *   <li>{@code PUT  /_matrix/client/v3/user/{userId}/account_data/{type}} — replace it.</li>
 * </ul>
 * {@code userId} is the FULL Matrix user id {@code @localpart:server}; {@code accessToken}
 * is the owner's decrypted custody token (a per-call argument — this client holds no
 * per-user credential, so one bean serves every owner).
 *
 * <p>STUB STATUS (mirrors {@link systems.snapdragon.userbff.profile.MatrixMediaClient}):
 * the live PUT/GET is GATED OFF by default (enabled only when a {@link WebClient} is wired
 * via {@code sticker.matrix.register.enabled=true}). When DISABLED both legs are no-ops —
 * {@link #getAccountData} resolves EMPTY (as if no pack is set) and {@link #setAccountData}
 * resolves a completed {@code Mono<Void>} after logging — so the registration flow ships
 * DARK and is fully unit-testable without a live homeserver. The access token is NEVER
 * logged.
 */
public class MatrixClientApiClient {

    private static final Logger log = LoggerFactory.getLogger(MatrixClientApiClient.class);

    /** Account-data read/write path; {@code userId}+{@code type} are URI-template vars
     *  (WebClient encodes them — no manual concatenation / injection surface). */
    private static final String ACCOUNT_DATA_PATH =
            "/_matrix/client/v3/user/{userId}/account_data/{type}";

    /** Off-codec JSON parse for the GET body (read-modify-write needs the current object).
     *  Mirrors {@code ServiceTokenBroker}: Boot 4's reactive codec is Jackson 3 and cannot
     *  decode into this Jackson-2 {@link JsonNode}; read as String + parse here. */
    private static final ObjectMapper MAPPER = new ObjectMapper();

    /** Null unless sticker.matrix.register.enabled=true — when null every call is a no-op stub. */
    private final WebClient http;

    public MatrixClientApiClient(WebClient http) {
        this.http = http;
    }

    /** Whether the live homeserver client is wired (false ⇒ dark/stub no-op mode). */
    public boolean isLive() {
        return http != null;
    }

    /**
     * Read the owner's current account-data object for {@code type}, as a generic
     * {@code Map<String,Object>} (the read half of read-modify-write). EMPTY when the
     * homeserver returns a 404 (no such account-data yet), when the body is blank, OR
     * when the client is in stub mode — every one of those is "no existing pack", which
     * the merge step treats as starting from an empty object. Fail-soft: an unexpected
     * homeserver error completes EMPTY (the caller proceeds with a fresh pack rather than
     * aborting the activation).
     *
     * @param matrixUserId the FULL Matrix user id {@code @localpart:server}.
     * @param type         the account-data type (e.g. {@code im.ponies.user_emotes}).
     * @param accessToken  the OWNER's decrypted homeserver-native token (per-call bearer).
     */
    public Mono<Map<String, Object>> getAccountData(String matrixUserId, String type, String accessToken) {
        if (http == null) {
            log.info("[matrix-c-s] (stub) GET account_data type={} for {} — live read disabled "
                    + "(sticker.matrix.register.enabled=false)", type, matrixUserId);
            return Mono.empty();
        }
        return http.get()
                .uri(ACCOUNT_DATA_PATH, matrixUserId, type)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
                // exchangeToMono lets us branch on the status BEFORE decoding: only a 2xx
                // body is parsed; a 404 (no account-data of this type yet — the common
                // first-pack case) OR any other non-2xx resolves EMPTY so the caller starts
                // from a fresh object. The body of a non-2xx is drained, never decoded.
                .exchangeToMono(resp -> {
                    if (resp.statusCode().is2xxSuccessful()) {
                        return resp.bodyToMono(String.class).flatMap(MatrixClientApiClient::parse);
                    }
                    // Drain the non-2xx body to release the connection, then EMPTY.
                    return resp.releaseBody().then(Mono.empty());
                })
                // A homeserver glitch must not abort the moderator's activation —
                // treat any read failure as "no existing pack" (fail-soft).
                .onErrorResume(e -> {
                    log.warn("[matrix-c-s] GET account_data type={} for {} failed (treating as empty): {}",
                            type, matrixUserId, e.toString());
                    return Mono.empty();
                });
    }

    /**
     * Replace the owner's account-data object for {@code type} with {@code content}
     * (the write half of read-modify-write). The body is the full object Matrix stores
     * verbatim. Returns a completed {@code Mono<Void>} on success; in stub mode it logs
     * and completes without any HTTP call.
     *
     * @param matrixUserId the FULL Matrix user id {@code @localpart:server}.
     * @param type         the account-data type (e.g. {@code im.ponies.user_emotes}).
     * @param content      the full account-data object to store.
     * @param accessToken  the OWNER's decrypted homeserver-native token (per-call bearer).
     */
    public Mono<Void> setAccountData(String matrixUserId, String type,
                                     Map<String, Object> content, String accessToken) {
        if (http == null) {
            log.info("[matrix-c-s] (stub) PUT account_data type={} for {} — live write disabled "
                    + "(sticker.matrix.register.enabled=false)", type, matrixUserId);
            return Mono.empty();
        }
        return http.put()
                .uri(ACCOUNT_DATA_PATH, matrixUserId, type)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(content == null ? Collections.emptyMap() : content)
                .retrieve()
                .toBodilessEntity()
                .then()
                .doOnSuccess(v -> log.info("[matrix-c-s] PUT account_data type={} for {} OK",
                        type, matrixUserId));
    }

    /** Parse a homeserver JSON body to a generic map; blank ⇒ EMPTY (no existing object). */
    private static Mono<Map<String, Object>> parse(String json) {
        if (json == null || json.isBlank()) {
            return Mono.empty();
        }
        try {
            JsonNode node = MAPPER.readTree(json);
            if (node == null || !node.isObject()) {
                return Mono.empty();
            }
            @SuppressWarnings("unchecked")
            Map<String, Object> map = MAPPER.convertValue(node, Map.class);
            return map == null ? Mono.empty() : Mono.just(map);
        } catch (JsonProcessingException | IllegalArgumentException e) {
            // A malformed body is treated as "no existing pack" (fail-soft).
            log.warn("[matrix-c-s] account_data body parse failed (treating as empty): {}", e.toString());
            return Mono.empty();
        }
    }
}
