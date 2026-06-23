package systems.snapdragon.userbff.media;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.snapdragon.userbff.media.MediaPoisoningProperties.FallbackMode;
import systems.snapdragon.userbff.media.PoisonModels.Backend;
import systems.snapdragon.userbff.media.PoisonModels.Health;
import systems.snapdragon.userbff.media.PoisonModels.PoisonResult;
import systems.snapdragon.commons.security.DomainRegistry;
import systems.snapdragon.commons.web.ApiException;

import java.util.List;
import java.util.Map;

/**
 * Orchestrates POISON-BEFORE-INGEST — the server-owned media-proxy.
 *
 * <h2>Responsibility</h2>
 *
 * <p>The UIs route image uploads through this service so bytes are AI-cloaked before
 * any homeserver sees them. The cloak policy and honest outcome are recorded
 * server-side. EVERY method takes the owner (the JWT subject) and records the
 * decision under that owner — the badge/repost source of truth can never be set by
 * the client.
 *
 * <h2>End-to-end reactive pipeline (image upload, mode != none, feature enabled)</h2>
 *
 * <pre>
 *   upload(owner, platform, requestedMode, bytes, ...)
 *       │
 *       ├─ [non-image by magic bytes OR mode=none OR feature-off]
 *       │        ▼
 *       │   forwardThrough(status="none")           ← upload unchanged + record
 *       │
 *       └─ [image, mode != none, feature on]
 *                │
 *                ▼
 *           worker.capability()                     ← GET /health
 *                │  Mono&lt;Health&gt;
 *                ├─ [backend = NONE  → heavy tier absent]
 *                │        ▼
 *                │   leanFallback(status="skipped") ← upload original + record
 *                │
 *                └─ [backend present]
 *                         ▼
 *                    worker.poison(bytes, mode, ...)     ← POST /poison
 *                         │  Mono&lt;PoisonResult&gt;
 *                         ├─ [empty/ok=false]
 *                         │       ▼
 *                         │   forwardThrough(status="failed") ← upload original + record
 *                         │
 *                         └─ [ok=true, poisonedOriginal present]
 *                                  ▼
 *                             homeserver.upload(platform, poisonedOriginal, ...)
 *                                  │  Mono&lt;Map&gt;  (homeserver response: id/url/mxc)
 *                                  ▼
 *                             survivalGate(platform, mode, poisoned, result, hs)
 *                                  │  Mono&lt;Boolean&gt;  (all served sizes still carry cloak)
 *                                  ▼
 *                             record(owner, ..., survived ? "protected" : "degraded")
 *                                  │  Mono&lt;MediaPoisonDecision&gt;
 *                                  ▼
 *                             UploadOutcome(homeserverResponse, decision)
 * </pre>
 *
 * <p>{@code mode=none} (opt-out) and a disabled feature forward straight through with
 * {@code status=none}. The expensive cloak only ever runs server-side, pre-ingest.
 *
 * @see MediaPoisonDecisionRepository
 * @see PoisonWorkerClient
 * @see HomeserverMediaClient
 * @see MediaPoisoningProperties
 */
@Service
public class MediaPoisonService {

    private static final Logger log = LoggerFactory.getLogger(MediaPoisonService.class);

    private final MediaPoisonDecisionRepository repo;
    private final PoisonWorkerClient worker;
    private final HomeserverMediaClient homeserver;
    private final MediaPoisoningProperties props;

    public MediaPoisonService(MediaPoisonDecisionRepository repo,
                              PoisonWorkerClient worker,
                              HomeserverMediaClient homeserver,
                              MediaPoisoningProperties props) {
        this.repo = repo;
        this.worker = worker;
        this.homeserver = homeserver;
        this.props = props;
    }

    // -------------------------------------------------------------------------
    // Public API
    // -------------------------------------------------------------------------

    /**
     * The result the controller returns to the UI: the homeserver response verbatim
     * (so the compose logic is untouched) + the server-owned AI-cloak decision.
     *
     * @param homeserver the raw homeserver upload response ({@code id}/{@code url}/
     *                   {@code content_uri} — whatever the platform returned)
     * @param decision   the durable {@code media_poison_decision} row, with the
     *                   honest {@code status} ({@code protected|degraded|skipped|
     *                   none|failed})
     */
    public record UploadOutcome(Map<String, Object> homeserver, MediaPoisonDecision decision) {}

    /**
     * Back-compat overload — stamps the decision in the platform {@code default} domain.
     *
     * @param owner               the caller's JWT subject
     * @param platform            {@code matrix|mastodon}
     * @param requestedMode       the UI's requested cloak mode ({@code glaze|
     *                            nightshade|light|none}); {@code null}/blank defaults
     *                            to the server's configured {@code defaultMode}
     * @param bytes               the raw upload bytes; must be non-empty and within
     *                            {@code maxUploadBytes}
     * @param filename            original filename (advisory; used as a worker hint)
     * @param declaredContentType the client-supplied Content-Type (advisory only;
     *                            the real type is sniffed from magic bytes)
     * @return a {@code Mono} emitting the {@link UploadOutcome}
     */
    public Mono<UploadOutcome> upload(String owner, String platform, String requestedMode,
                                      byte[] bytes, String filename, String declaredContentType) {
        return upload(owner, platform, requestedMode, bytes, filename, declaredContentType,
                DomainRegistry.DEFAULT_DOMAIN);
    }

    /**
     * Poison-then-forward (or forward-through) one upload.
     *
     * <p>{@code owner} is the JWT subject (never a body field).
     * {@code requestedMode} is the UI's choice; the service resolves the effective
     * mode + honest status server-side (sniffs bytes, probes worker, runs gate).
     *
     * @param owner               the caller's JWT subject (never a request field)
     * @param platform            {@code matrix|mastodon}
     * @param requestedMode       the UI's requested cloak mode; defaults to
     *                            {@link MediaPoisoningProperties#getDefaultMode()}
     *                            when null/blank
     * @param bytes               raw upload bytes; must be non-empty and within
     *                            the configured {@code maxUploadBytes}
     * @param filename            original filename (advisory; forwarded to the
     *                            worker and the homeserver)
     * @param declaredContentType advisory client Content-Type; the actual type is
     *                            always re-sniffed from magic bytes server-side
     * @param domain              the caller's validated-issuer brand; {@code null}
     *                            = SUPERADMIN cross-domain bypass
     * @return a {@code Mono} emitting the {@link UploadOutcome}
     * @throws ApiException 400 on invalid {@code platform}, invalid {@code mode},
     *                      empty bytes, or bytes exceeding the max size
     */
    public Mono<UploadOutcome> upload(String owner, String platform, String requestedMode,
                                      byte[] bytes, String filename, String declaredContentType,
                                      String domain) {
        requireOwner(owner);
        if (!MediaPoisonDecision.validPlatform(platform)) {
            return Mono.error(ApiException.badRequest("platform must be matrix|mastodon"));
        }
        String mode = (requestedMode == null || requestedMode.isBlank())
                ? props.getDefaultMode() : requestedMode.trim();
        if (!MediaPoisonDecision.validMode(mode)) {
            return Mono.error(ApiException.badRequest("mode must be glaze|nightshade|light|none"));
        }
        if (bytes == null || bytes.length == 0) {
            return Mono.error(ApiException.badRequest("empty upload"));
        }
        if (bytes.length > props.getMaxUploadBytes()) {
            return Mono.error(ApiException.badRequest("upload exceeds max size"));
        }

        // The TRUE content type is sniffed from bytes; the client header is advisory only.
        String sniffed = ImageSniffer.detect(bytes);
        boolean isImage = sniffed != null;
        String contentType = sniffed != null ? sniffed
                : declaredContentType == null ? "application/octet-stream" : declaredContentType;

        // Opt-out / feature-off / non-image ⇒ forward through UNCHANGED, status=none.
        if ("none".equals(mode) || !props.isEnabled() || !isImage) {
            String why = !isImage ? "non-image" : "none".equals(mode) ? "opt-out" : "feature-off";
            log.info("[media] forward-through ({}) platform={} owner={}", why, platform, owner);
            return forwardThrough(owner, platform, mode, "none", null, bytes, filename, contentType, domain);
        }

        // Probe the worker once: ABSENT ⇒ lean fallback; PRESENT ⇒ cloak.
        return worker.capability().flatMap(health -> {
            Backend backend = Backend.parse(health.backend());
            if (!backend.present()) {
                return leanFallback(owner, platform, mode, bytes, filename, contentType, domain);
            }
            return cloakThenForward(owner, platform, mode, backend, bytes, filename, contentType, domain);
        });
    }

    // -------------------------------------------------------------------------
    // Pipeline stages
    // -------------------------------------------------------------------------

    /**
     * The lean fallback when the heavy tier is absent. Default behaviour ({@code skip}):
     * forward the ORIGINAL through with {@code status=skipped} so the UI can warn
     * "not cloaked". {@code light}/{@code queue} also forward-through here — the
     * light-CPU/queue paths attach to a PRESENT worker; an ABSENT worker can do
     * neither — but the configured intent is recorded so telemetry distinguishes the gap.
     *
     * @param owner       the caller's JWT subject (for the decision row)
     * @param platform    target homeserver platform
     * @param mode        the originally-requested cloak mode (recorded in the row)
     * @param bytes       the upload bytes (forwarded unchanged)
     * @param filename    original filename
     * @param contentType sniffed content type
     * @param domain      caller's tenant domain
     * @return a {@code Mono} emitting the {@link UploadOutcome} with
     *         {@code status=skipped}
     */
    private Mono<UploadOutcome> leanFallback(String owner, String platform, String mode,
                                             byte[] bytes, String filename, String contentType,
                                             String domain) {
        FallbackMode fb = props.fallback();
        log.warn("[media] heavy tier ABSENT — fallback={} ⇒ forward UNCLOAKED platform={} owner={}",
                fb, platform, owner);
        return forwardThrough(owner, platform, mode, "skipped", Backend.NONE.wire(),
                bytes, filename, contentType, domain);
    }

    /**
     * Poison the bytes (original + every pinned served size), upload the POISONED
     * original via the mTLS proxy, then run the survival gate. On worker failure:
     * record {@code failed} and forward the ORIGINAL through (never a false
     * {@code protected}).
     *
     * @param owner    the caller's JWT subject
     * @param platform target homeserver platform
     * @param mode     the cloak mode ({@code glaze|nightshade|light})
     * @param probed   the worker backend reported by the {@code /health} probe
     * @param bytes    the raw original upload bytes
     * @param filename original filename
     * @param contentType sniffed content type
     * @param domain   caller's tenant domain
     * @return a {@code Mono} emitting the {@link UploadOutcome} with
     *         {@code status=protected|degraded|failed|skipped}
     */
    private Mono<UploadOutcome> cloakThenForward(String owner, String platform, String mode,
                                                 Backend probed, byte[] bytes, String filename,
                                                 String contentType, String domain) {
        return worker.poison(bytes, mode, filename, contentType, props.getThumbnailSizes())
                // route the worker result: a failed/empty cloak forwards the ORIGINAL,
                // a good cloak runs the upload+gate+record ladder (extracted helper).
                .flatMap(result -> onPoisonResult(result, owner, platform, mode, probed,
                        bytes, filename, contentType, domain))
                // poison() emitted empty (no worker wired despite a present probe) ⇒ skip
                // honestly. DEFERRED so the forward-through upload only runs on the empty
                // path (not eagerly at assembly time).
                .switchIfEmpty(Mono.defer(() -> forwardThrough(owner, platform, mode, "skipped",
                        probed.wire(), bytes, filename, contentType, domain)));
    }

    /**
     * Dispatch on the worker's poison result. A {@code null}/{@code !ok}/empty result
     * forwards the ORIGINAL with {@code status=failed} (never a false "protected"); a good
     * result resolves the backend that ran and runs {@link #uploadAndGate} on the poisoned
     * bytes. Extracted from {@link #cloakThenForward} so the 3-deep upload→gate→record
     * ladder is a named step, not an inline nested lambda.
     */
    private Mono<UploadOutcome> onPoisonResult(PoisonResult result, String owner, String platform,
                                               String mode, Backend probed, byte[] bytes,
                                               String filename, String contentType, String domain) {
        if (result == null || !result.ok() || result.poisonedOriginal() == null) {
            log.warn("[media] worker poison failed/empty ⇒ forward original, status=failed");
            return forwardThrough(owner, platform, mode, "failed",
                    backendOf(result, probed), bytes, filename, contentType, domain);
        }
        // the backend the worker actually ran (fall back to the probed tier if it didn't say).
        Backend ran = Backend.parse(result.backend());
        Backend backend = ran.present() ? ran : probed;
        return uploadAndGate(owner, platform, mode, backend, result, filename, contentType, domain);
    }

    /**
     * Upload the POISONED original via the mTLS proxy, run the round-trip survival gate,
     * and record the honest decision — the inner ladder de-nested out of {@link
     * #cloakThenForward}. {@code status=protected} ONLY when the gate passes, else
     * {@code degraded}. Behaviour is identical to the prior inline chain.
     */
    private Mono<UploadOutcome> uploadAndGate(String owner, String platform, String mode,
                                              Backend backend, PoisonResult result,
                                              String filename, String contentType, String domain) {
        byte[] poisoned = result.poisonedOriginal();
        // 1) real homeserver upload of the poisoned bytes.
        return homeserver.upload(platform, poisoned, filename, contentType)
                // 2) re-fetch the served artifacts and run the perturbation-survival gate.
                .flatMap(hs -> survivalGate(platform, mode, poisoned, result, hs)
                        // 3) record the honest decision and pair it with the homeserver response.
                        .flatMap(survived -> recordOutcome(owner, platform, mode, backend, domain,
                                survived, hs)));
    }

    /** Record the honest decision for an uploaded+gated artifact and pair it with the
     *  verbatim homeserver response. {@code protected} iff the gate passed, else {@code
     *  degraded}. Split out so {@link #uploadAndGate} stays a flat 3-operator chain. */
    private Mono<UploadOutcome> recordOutcome(String owner, String platform, String mode,
                                              Backend backend, String domain, boolean survived,
                                              Map<String, Object> hs) {
        String status = survived ? "protected" : "degraded";
        return record(owner, platform, mediaRef(platform, hs), mode, status, backend.wire(), domain)
                .map(dec -> new UploadOutcome(hs, dec));
    }

    /**
     * ROUND-TRIP SURVIVAL GATE: re-fetch the served original + each pinned thumbnail
     * size and run the perturbation-presence check ({@link PoisonWorkerClient#checkSurvival}).
     * The cloak is counted as surviving ONLY if the original AND every re-fetched
     * thumbnail still carry the perturbation.
     *
     * <p>Fail-honest: a thumbnail we could not re-fetch counts as
     * not-surviving (the gate never auto-passes on a fetch error). If the homeserver
     * response exposes no re-fetchable served URLs, the gate falls back to checking
     * the poisoned bytes we hold (pre-transcode) — still a real check, not a skip.
     *
     * @param platform        target platform ({@code matrix} or {@code mastodon});
     *                        used to derive served URL paths from the HS response
     * @param mode            the cloak mode that was applied (forwarded to the check)
     * @param poisonedOriginal the poisoned bytes from the worker (used if no HS URLs)
     * @param result          the poison result returned by the worker
     * @param hs              the homeserver upload response (contains served URL hints)
     * @return a {@code Mono<true>} when every served artifact still carries the
     *         perturbation, {@code Mono<false>} when any artifact failed the check
     */
    Mono<Boolean> survivalGate(String platform, String mode, byte[] poisonedOriginal,
                               PoisonResult result, Map<String, Object> hs) {
        List<String> servedUrls = servedUrls(platform, hs);
        Flux<Boolean> checks;
        if (servedUrls.isEmpty()) {
            // No re-fetchable served URL: check the bytes we hold (pre-transcode) so the
            // gate is a real check, not an auto-pass.
            checks = worker.checkSurvival(poisonedOriginal, mode, "original").map(v -> v.present()).flux();
        } else {
            checks = Flux.fromIterable(servedUrls)
                    .concatMap(url -> homeserver.fetchServed(platform, url)
                            .flatMap(served -> worker.checkSurvival(served, mode, sizeLabel(url)))
                            // a served artifact we could not re-fetch = NOT a survival.
                            .defaultIfEmpty(new PoisonModels.SurvivalVerdict(false, null, "refetch empty"))
                            .map(v -> v.present()));
        }
        return checks.all(Boolean::booleanValue);
    }

    /** Record-only forward-through: upload the bytes unchanged, record the decision. */
    private Mono<UploadOutcome> forwardThrough(String owner, String platform, String mode,
                                               String status, String backend, byte[] bytes,
                                               String filename, String contentType, String domain) {
        return homeserver.upload(platform, bytes, filename, contentType)
                .flatMap(hs -> record(owner, platform, mediaRef(platform, hs), mode, status, backend, domain)
                        .map(dec -> new UploadOutcome(hs, dec)));
    }

    private Mono<MediaPoisonDecision> record(String owner, String platform, String mediaRef,
                                             String mode, String status, String backend, String domain) {
        return repo.record(owner, platform, mediaRef, mode, status, backend, domain)
                .doOnSuccess(d -> log.info("[media] decision recorded owner={} platform={} ref={} mode={} status={} backend={}",
                        owner, platform, mediaRef, mode, status, backend));
    }

    /** The caller's capability view (worker backend + offered modes + ETA) for the badge. */
    public Mono<Health> capability() {
        return worker.capability();
    }

    /**
     * Back-compat overload — scopes to the platform {@code default} domain.
     *
     * @param owner    the caller's JWT subject
     * @param mediaRef the homeserver media reference ({@code content_uri} / akkoma id)
     * @return a {@code Mono} emitting the most-recent decision, or 404
     */
    public Mono<MediaPoisonDecision> status(String owner, String mediaRef) {
        return status(owner, mediaRef, DomainRegistry.DEFAULT_DOMAIN);
    }

    /**
     * The caller's most-recent {@code media_poison_decision} for a media reference
     * (the badge poll + already-cloaked repost guard). Owner-AND-domain-AND-ref
     * scoped ({@code domain} null = SUPERADMIN cross-domain bypass).
     *
     * @param owner    the caller's JWT subject (never a request field)
     * @param mediaRef the homeserver media reference ({@code mxc://...} for Matrix,
     *                 the akkoma attachment id for Mastodon)
     * @param domain   the caller's validated-issuer brand; {@code null} = SUPERADMIN
     *                 cross-domain bypass
     * @return a {@code Mono} emitting the most-recent decision row
     * @throws ApiException 404 when no decision is found for this media in this domain
     */
    public Mono<MediaPoisonDecision> status(String owner, String mediaRef, String domain) {
        requireOwner(owner);
        return repo.findByOwnerAndRef(owner, mediaRef, domain)
                .switchIfEmpty(Mono.error(ApiException.notFound("no decision for this media")));
    }

    // -------------------------------------------------------------------------
    // Status query
    // -------------------------------------------------------------------------

    /** The caller's capability view (worker backend + offered modes + ETA) for the
     *  media-poison badge. See {@link PoisonWorkerClient#capability()}.
     *
     * @return a {@code Mono} emitting the current worker {@link PoisonModels.Health};
     *         never errors — a missing worker resolves to {@code backend=none}
     */

    // (capability() body below)

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private static String backendOf(PoisonResult r, Backend probed) {
        Backend b = r == null ? Backend.NONE : Backend.parse(r.backend());
        return (b.present() ? b : probed).wire();
    }

    /**
     * Extract the homeserver media reference EXACTLY as the homeserver returned it —
     * {@code content_uri} ({@code mxc://...}) for Matrix, the attachment {@code id}
     * field for akkoma/Mastodon.  Returns {@code null} when the response carries no
     * recognisable ref (abnormal but non-fatal — the decision row records {@code null}).
     *
     * @param platform the target platform ({@code matrix} or {@code mastodon})
     * @param hs       the homeserver upload response map
     * @return the media ref string, or {@code null}
     */
    static String mediaRef(String platform, Map<String, Object> hs) {
        if (hs == null) return null;
        if ("matrix".equals(platform)) {
            Object uri = hs.get("content_uri");
            return uri == null ? null : uri.toString();
        }
        Object id = hs.get("id");
        return id == null ? null : id.toString();
    }

    /**
     * The re-fetchable served URLs from the homeserver upload response, used by
     * {@link #survivalGate} to verify the perturbation survived homeserver
     * transcoding.  For Matrix: derives {@code /_matrix/media/v3/download/...} and
     * {@code /_matrix/media/v3/thumbnail/...} from the {@code content_uri} ({@code mxc://}).
     * For akkoma/Mastodon: extracts {@code url} (original) and {@code preview_url}
     * (small preview).
     *
     * @param platform the target platform ({@code matrix} or {@code mastodon})
     * @param hs       the homeserver upload response map
     * @return a non-null list of re-fetchable served URL strings; empty when none
     */
    static List<String> servedUrls(String platform, Map<String, Object> hs) {
        var out = new java.util.ArrayList<String>();
        if (hs == null) return out;
        if ("matrix".equals(platform)) {
            Object uri = hs.get("content_uri");
            String mxc = uri == null ? null : uri.toString();
            if (mxc != null && mxc.startsWith("mxc://")) {
                String body = mxc.substring("mxc://".length());
                int slash = body.indexOf('/');
                if (slash > 0) {
                    String server = body.substring(0, slash);
                    String id = body.substring(slash + 1);
                    out.add("/_matrix/media/v3/download/" + server + "/" + id);
                    // the pinned Matrix thumbnail size (240x240).
                    out.add("/_matrix/media/v3/thumbnail/" + server + "/" + id
                            + "?width=240&height=240&method=scale");
                }
            }
            return out;
        }
        // akkoma/Mastodon: the served original + the "small" preview.
        addUrl(out, hs.get("url"));
        addUrl(out, hs.get("preview_url"));
        return out;
    }

    private static void addUrl(List<String> out, Object v) {
        if (v != null && !v.toString().isBlank()) out.add(v.toString());
    }

    /** A coarse size label for a served URL (for the survival verdict log). */
    private static String sizeLabel(String url) {
        if (url == null) return "original";
        if (url.contains("thumbnail") || url.contains("preview")) return "thumbnail";
        if (url.contains("240")) return "240x240";
        return "original";
    }

    private static void requireOwner(String owner) {
        if (owner == null || owner.isBlank()) {
            throw ApiException.unauthorized("missing authenticated subject");
        }
    }
}
