package systems.snapdragon.userbff.federation;

import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DefaultDataBufferFactory;
import org.springframework.http.MediaType;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.util.UriBuilder;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.snapdragon.userbff.federation.FederationModerationModels.SubmitRequest;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Reactive WebClient CLIENT of snapdragon-federation-api. The base URL defaults to
 * the in-cluster DNS {@code http://snapdragon-federation-api.snapdragon-backend
 * .svc.cluster.local:8080} (env-overridable). The bearer token is injected per
 * request by the {@link FederationWebClientConfig} token-forwarding
 * {@code ExchangeFilterFunction}, so federation-api scopes every call to the SAME
 * Casdoor subject as the caller — owner-enforcement is preserved end-to-end.
 *
 * <p>Endpoints used (matched field-for-field to the federation-api controllers):
 * <ul>
 *   <li>GET  {@code /api/federation/bundles/mine} — the caller's own cards;</li>
 *   <li>GET  {@code /api/federation/bundles/slug/{slug}} — versions for a slug;</li>
 *   <li>PUT  {@code /api/federation/bundles/{slug}} — publish a bundle (octet-stream
 *       body + entryFile/visibility/manifest query params);</li>
 *   <li>POST {@code /api/federation/moderation} — submit a moderation request
 *       (kind=instance-block; status is set to 'recommended' server-side).</li>
 * </ul>
 */
public class FederationApiClient {

    private final WebClient http;

    public FederationApiClient(WebClient http) {
        this.http = http;
    }

    /** The caller's OWN bundle cards (federation-api scopes /mine to the JWT subject). */
    public Flux<UserModuleCard> listMine() {
        return http.get()
                .uri("/api/federation/bundles/mine")
                .retrieve()
                .bodyToFlux(UserModuleCard.class);
    }

    /** Versions of the caller's bundle for a slug. */
    public Flux<UserModuleCard> listBySlug(String slug) {
        return http.get()
                .uri(uri -> uri.path("/api/federation/bundles/slug/{slug}").build(slug))
                .retrieve()
                .bodyToFlux(UserModuleCard.class);
    }

    /**
     * Publish (PUT) a bundle for a slug. The body is the single entry file as an
     * octet-stream; entryFile/visibility/manifest are optional query params. The
     * forwarded JWT makes federation-api record the bundle under the caller as
     * owner.
     */
    public Mono<UserModuleCard> put(String slug, String entryFile, String visibility,
                                    String manifestJson, byte[] body) {
        DataBuffer buf = new DefaultDataBufferFactory()
                .wrap(body == null ? new byte[0] : body);
        return http.put()
                .uri(uri -> {
                    UriBuilder b = uri.path("/api/federation/bundles/{slug}");
                    if (entryFile != null)   b.queryParam("entryFile", entryFile);
                    if (visibility != null)  b.queryParam("visibility", visibility);
                    if (manifestJson != null) b.queryParam("manifest", manifestJson);
                    return b.build(slug);
                })
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .body(Flux.just(buf), DataBuffer.class)
                .retrieve()
                .bodyToMono(UserModuleCard.class);
    }

    /**
     * Start the recommend-instance-block chain: POST a moderation request to
     * federation-api with {@code kind=instance-block}. federation-api's
     * {@code ModerationController.submit} sets the status to {@code recommended}
     * server-side (the chain start: USER recommends -> MOD refers -> ADMIN decides).
     * The request body is the federation {@code SubmitRequest(kind, target, reason)}.
     */
    public Mono<Map<String, Object>> recommendInstanceBlock(String instance, String reason) {
        SubmitRequest req = new SubmitRequest("instance-block", instance, reason);
        return http.post()
                .uri("/api/federation/moderation")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(req)
                .retrieve()
                .bodyToMono(MAP_TYPE);
    }

    @SuppressWarnings("unchecked")
    private static final Class<Map<String, Object>> MAP_TYPE = (Class<Map<String, Object>>) (Class<?>) Map.class;

    /** UTF-8 bytes for a string body (small helper kept for callers). */
    static byte[] bytes(String s) {
        return s == null ? new byte[0] : s.getBytes(StandardCharsets.UTF_8);
    }

    /** Build a query map (kept for symmetry/testability). */
    static MultiValueMap<String, String> q(Map<String, String> in) {
        MultiValueMap<String, String> out = new org.springframework.util.LinkedMultiValueMap<>();
        Map<String, String> copy = new LinkedHashMap<>(in);
        copy.forEach((k, v) -> { if (v != null) out.add(k, v); });
        return out;
    }
}
