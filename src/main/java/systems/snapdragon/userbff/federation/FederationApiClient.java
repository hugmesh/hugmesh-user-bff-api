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
 *   <li>GET  {@code /api/federation/bundles/slug/{slug}/body} — the caller's own
 *       current card body bytes (read-my-card-body, for Edit pre-fill);</li>
 *   <li>PUT  {@code /api/federation/bundles/{slug}} — publish a bundle (octet-stream
 *       body + entryFile/visibility/manifest query params);</li>
 *   <li>DELETE {@code /api/federation/bundles/{slug}} — delete the caller's own
 *       current bundle for a slug;</li>
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
     * READ the caller's OWN current card body (source bytes) for a slug — proxies
     * federation-api's owner-scoped {@code GET /bundles/slug/{slug}/body}. The
     * forwarded JWT makes federation-api return ONLY the caller's own card (a
     * non-owner gets 404 upstream), so the WYSIWYG editor can pre-fill for Edit.
     * Returns the raw entry-file bytes (the card source), not JSON.
     */
    public Mono<byte[]> readBody(String slug) {
        return http.get()
                .uri(uri -> uri.path("/api/federation/bundles/slug/{slug}/body").build(slug))
                .retrieve()
                .bodyToMono(byte[].class);
    }

    /**
     * DELETE the caller's OWN current bundle for a slug — proxies federation-api's
     * owner-scoped {@code DELETE /bundles/{slug}}. The forwarded JWT makes
     * federation-api delete ONLY the caller's own card (a non-owner gets 404
     * upstream); federation-api removes the storage version + supersedes the row.
     */
    public Mono<Void> delete(String slug) {
        return http.delete()
                .uri(uri -> uri.path("/api/federation/bundles/{slug}").build(slug))
                .retrieve()
                .bodyToMono(Void.class);
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

    /**
     * SELF-SILENCE leg 1 — hide the caller's own public federation profile so the
     * public vanity resolve returns 404 while they are self-silenced. This is a
     * SELF-hide (it must NOT hide the user from THEMSELVES — their own profile is an
     * authenticated route that does not consult the public vanity resolve), and it is
     * DISTINCT from an admin ban override (a different scope/marker), so an expiry
     * un-hide never re-arms an unrelated admin kill.
     *
     * <p>CONTRACT (the federation-api user-scope hide-profile apply path is a LATER
     * phase): {@code POST /api/federation/self-silence/hide-profile} with the caller's
     * forwarded JWT — federation-api records a {@code scope=user, action=hide-profile}
     * override keyed to the JWT subject, with NO module-existence requirement (so a
     * user with no published profile can still self-silence). Until that endpoint
     * ships, the caller (SelfSilenceService) keeps this leg GATED + fail-CLOSED so a
     * not-yet-deployed federation leg never hard-fails activation — the durable
     * {@code self_silence} row is the source of truth and the seam converges later.
     */
    public Mono<Void> applyHideProfile() {
        return http.post()
                .uri("/api/federation/self-silence/hide-profile")
                .retrieve()
                .toBodilessEntity()
                .then();
    }

    /**
     * SELF-SILENCE un-hide (leg 1 reverse) — clear the caller's own hide-profile
     * self-silence override so the public profile resolves again. Clears ONLY the
     * self-silence-scoped marker (never an admin ban override). Mirrors
     * {@link #applyHideProfile()}; same forwarded-JWT, same gated/fail-closed contract.
     * Endpoint: {@code DELETE /api/federation/self-silence/hide-profile}.
     */
    public Mono<Void> clearHideProfile() {
        return http.delete()
                .uri("/api/federation/self-silence/hide-profile")
                .retrieve()
                .toBodilessEntity()
                .then();
    }

    /**
     * SELF-SILENCE early-reactivate — request a moderator/admin reactivation by
     * writing a {@code kind='self-silence-appeal'} moderation request (the row IS the
     * queue mods already watch; NOT literal SMTP). The forwarded JWT records it under
     * the caller; {@code target} is the caller's own subject, {@code reason} their note.
     * Reuses the existing {@code POST /api/federation/moderation} surface; federation-
     * api sets the status server-side. The {@code self-silence-appeal} kind itself is
     * added to federation-api's moderation vocabulary in a paired later phase — until
     * then this is the documented transport for the email-mod seam.
     */
    public Mono<Map<String, Object>> requestSelfSilenceReactivation(String subject, String reason) {
        SubmitRequest req = new SubmitRequest("self-silence-appeal", subject, reason);
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
