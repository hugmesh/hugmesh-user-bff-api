package net.hugmesh.userbff.federation;

import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DefaultDataBufferFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import org.springframework.web.util.UriBuilder;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.commons.web.ApiException;
import net.hugmesh.userbff.federation.FederationModerationModels.FindingRequest;
import net.hugmesh.userbff.federation.FederationModerationModels.RecommendInstanceBlockRequest;
import net.hugmesh.userbff.federation.FederationModerationModels.SubmitRequest;

import java.util.Map;

/**
 * Reactive WebClient CLIENT of hugmesh-federation-api. The base URL defaults to
 * the in-cluster DNS {@code http://hugmesh-federation-api.hugmesh-backend
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
 *   <li>POST {@code /api/federation/moderation/recommend-instance-block} — the
 *       recommend-instance-block chain start (self-service; ROLE_MATRIX/MASTODON
 *       gated at federation-api; status is set to 'recommended' server-side).</li>
 *   <li>PUT/DELETE {@code /api/federation/vanity/{username}} — self-publish /
 *       self-unpublish the caller's vanity profile fragment (see
 *       {@link #publishVanity(String, String)} / {@link #unpublishVanity(String)}).</li>
 * </ul>
 */
public class FederationApiClient {

    private final WebClient http;

    public FederationApiClient(WebClient http) {
        this.http = http;
    }

    /** The caller's OWN bundle cards (federation-api scopes /mine to the JWT subject).
     *  Upstream statuses pass through honestly (see {@link #toApiException}). */
    public Flux<UserModuleCard> listMine() {
        return http.get()
                .uri("/api/federation/bundles/mine")
                .retrieve()
                .bodyToFlux(UserModuleCard.class)
                .onErrorMap(WebClientResponseException.class,
                        ex -> toApiException(ex, "list cards"));
    }

    /** Versions of the caller's bundle for a slug. Upstream statuses pass through
     *  honestly (see {@link #toApiException}). */
    public Flux<UserModuleCard> listBySlug(String slug) {
        return http.get()
                .uri(uri -> uri.path("/api/federation/bundles/slug/{slug}").build(slug))
                .retrieve()
                .bodyToFlux(UserModuleCard.class)
                .onErrorMap(WebClientResponseException.class,
                        ex -> toApiException(ex, "list card versions"));
    }

    /**
     * READ the caller's OWN current card body (source bytes) for a slug — proxies
     * federation-api's owner-scoped {@code GET /bundles/slug/{slug}/body}. The
     * forwarded JWT makes federation-api return ONLY the caller's own card (a
     * non-owner gets 404 upstream), so the WYSIWYG editor can pre-fill for Edit.
     * Returns the raw entry-file bytes (the card source), not JSON.
     *
     * <p><b>Honest status pass-through</b>: federation-api's owner-scoped 404 (a
     * foreign or unknown slug) maps to an {@link ApiException} carrying the SAME
     * status — the semantically-correct 404 the cards UI needs, not the untranslated
     * 500 two e2e feature files used to have to tolerate ("one of 404 or 500").
     */
    public Mono<byte[]> readBody(String slug) {
        return http.get()
                .uri(uri -> uri.path("/api/federation/bundles/slug/{slug}/body").build(slug))
                .retrieve()
                .bodyToMono(byte[].class)
                .onErrorMap(WebClientResponseException.class,
                        ex -> toApiException(ex, "read card body"));
    }

    /**
     * DELETE the caller's OWN current bundle for a slug — proxies federation-api's
     * owner-scoped {@code DELETE /bundles/{slug}}. The forwarded JWT makes
     * federation-api delete ONLY the caller's own card (a non-owner gets 404
     * upstream); federation-api removes the storage version + supersedes the row.
     * Upstream statuses pass through honestly (a cross-owner delete surfaces as the
     * 404 federation-api returned — see {@link #toApiException}).
     */
    public Mono<Void> delete(String slug) {
        return http.delete()
                .uri(uri -> uri.path("/api/federation/bundles/{slug}").build(slug))
                .retrieve()
                .bodyToMono(Void.class)
                .onErrorMap(WebClientResponseException.class,
                        ex -> toApiException(ex, "delete card"));
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
                .bodyToMono(UserModuleCard.class)
                .onErrorMap(WebClientResponseException.class,
                        ex -> toApiException(ex, "publish card"));
    }

    /**
     * Start the recommend-instance-block chain: POST to federation-api's narrower,
     * self-service {@code /api/federation/moderation/recommend-instance-block}
     * surface (kind is hardcoded server-side to {@code instance-block}; status to
     * {@code recommended} — the chain start: USER files -> MOD refers -> ADMIN
     * decides). The request body is the federation
     * {@code RecommendInstanceBlockRequest(target, reason)}.
     *
     * <p><b>NOT</b> {@code POST /api/federation/moderation} (the mod/admin-only
     * {@code SubmitRequest} surface) — that path's {@code hasAnyRole('MOD','ADMIN',
     * 'SUPERADMIN')} path-level gate has no {@code RoleHierarchy} edge that admits a
     * plain {@code ROLE_MATRIX}/{@code ROLE_MASTODON} caller, so a call to it from
     * here always 403'd downstream (this endpoint's forwarded bearer is the
     * caller's OWN, never a mod/admin's — see {@link
     * net.hugmesh.userbff.block.BlockController#recommendInstanceBlock}).
     * See {@link RecommendInstanceBlockRequest}'s javadoc for the full root-cause
     * writeup.
     */
    public Mono<Map<String, Object>> recommendInstanceBlock(String instance, String reason) {
        RecommendInstanceBlockRequest req = new RecommendInstanceBlockRequest(instance, reason);
        return http.post()
                .uri("/api/federation/moderation/recommend-instance-block")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(req)
                .retrieve()
                .bodyToMono(MAP_TYPE);
    }

    /**
     * File an automated edge-AI moderation finding into the federation {@code @system}
     * findings queue ({@code POST /api/federation/findings}). The caller's bearer is
     * forwarded, so federation derives {@code subject} = the caller's JWT subject (a user
     * can only ever file a finding about THEIR OWN content) and stamps
     * {@code reporter="@system"} + {@code status="held"} server-side. The body is the
     * federation {@code FileRequest(surface, disposition, classification, confidence,
     * policyHit, perceptualHash)}. Returns the created finding (callers that file
     * fire-and-forget ignore the body).
     */
    public Mono<Map<String, Object>> fileFinding(FindingRequest req) {
        return http.post()
                .uri("/api/federation/findings")
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

    /**
     * SELF-PUBLISH the caller's vanity profile — proxies federation-api's
     * owner-scoped {@code PUT /api/federation/vanity/{username}}. federation-api
     * upserts the {@code profile-<username>} fragment FROM the caller's own
     * already-uploaded bundle (see {@link #put}); {@code remoteEntryUrl} /
     * {@code contentHash} are derived server-side there, never sent from here.
     *
     * <p><b>Honest failure</b>: a non-2xx upstream response (404 = no bundle
     * uploaded yet; 400 = reserved/confusable username; 403 = not the bundle's
     * owner) is mapped to an {@link ApiException} carrying the SAME status, so the
     * caller (ProfileService) sees a real failure — never a silently-downgraded
     * success. See {@link #toApiException(WebClientResponseException, String)}.
     *
     * @param username    the caller's own (already-normalized) vanity username
     * @param displayName optional display name to stamp on the fragment; {@code
     *                    null}/blank omits the field (federation-api keeps the
     *                    existing/derived name)
     * @return a {@code Mono} emitting the upserted fragment's wire shape
     */
    public Mono<Map<String, Object>> publishVanity(String username, String displayName) {
        Map<String, Object> body = (displayName == null || displayName.isBlank())
                ? Map.of() : Map.of("displayName", displayName);
        return http.put()
                .uri(uri -> uri.path("/api/federation/vanity/{username}").build(username))
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(body)
                .retrieve()
                .bodyToMono(MAP_TYPE)
                .onErrorMap(WebClientResponseException.class,
                        ex -> toApiException(ex, "publish vanity profile"));
    }

    /**
     * SELF-UNPUBLISH the caller's vanity profile — proxies federation-api's
     * owner-scoped {@code DELETE /api/federation/vanity/{username}}. Idempotent
     * upstream (a no-op when the profile was never published); still mapped to a
     * real {@link ApiException} on failure (see {@link #publishVanity}) so a
     * transient federation-api outage is never reported as "unpublished".
     *
     * @param username the caller's own (already-normalized) vanity username
     * @return a {@code Mono<Void>} completing once federation-api confirms
     */
    public Mono<Void> unpublishVanity(String username) {
        return http.delete()
                .uri(uri -> uri.path("/api/federation/vanity/{username}").build(username))
                .retrieve()
                .toBodilessEntity()
                .then()
                .onErrorMap(WebClientResponseException.class,
                        ex -> toApiException(ex, "unpublish vanity profile"));
    }

    /**
     * Maps a raw {@link WebClientResponseException} from a cards or vanity call to an
     * {@link ApiException} carrying the SAME HTTP status federation-api returned
     * (falling back to {@code BAD_GATEWAY} for a status Spring cannot resolve), with
     * the upstream response body appended for diagnostics. This is the
     * honest-propagation seam: a downstream caller (ProfileService, CardsController)
     * sees the real failure reason — federation-api's owner-scoped 404 stays a 404 at
     * the BFF boundary instead of leaking as an untranslated generic 500 (the defect
     * two user-ui e2e feature files documented as "one of 404 or 500"), and a
     * "publish" can never report a success it did not achieve.
     */
    private static ApiException toApiException(WebClientResponseException ex, String action) {
        HttpStatus status = HttpStatus.resolve(ex.getStatusCode().value());
        String detail = ex.getResponseBodyAsString();
        String message = "federation " + action + " failed (HTTP " + ex.getStatusCode().value() + ")"
                + (detail == null || detail.isBlank() ? "" : ": " + detail);
        return new ApiException(status != null ? status : HttpStatus.BAD_GATEWAY, message);
    }

    @SuppressWarnings("unchecked")
    private static final Class<Map<String, Object>> MAP_TYPE = (Class<Map<String, Object>>) (Class<?>) Map.class;
}
