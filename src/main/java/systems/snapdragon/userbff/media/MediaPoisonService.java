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
 * Orchestrates POISON-BEFORE-INGEST: the server-owned media-proxy that the UIs route
 * uploads through so bytes are AI-cloaked before any homeserver sees them, owning every
 * served size, with the policy recorded server-side. EVERY method takes the owner (the
 * JWT subject) and records the decision under that owner — the badge/repost source of
 * truth can never be set by the client.
 *
 * <p>The flow for an image with {@code mode != none} (and the feature enabled):
 * <ol>
 *   <li>magic-byte sniff (server-side, never the client Content-Type): a NON-image is
 *       forwarded through unchanged with {@code status=none};</li>
 *   <li>probe the worker {@code /health}: ABSENT (backend none) ⇒ the LEAN FALLBACK
 *       (forward-through + {@code status=skipped}, or the light-CPU path if configured
 *       and the worker offers CPU) so the post is never blocked and the UI can warn
 *       "not cloaked";</li>
 *   <li>PRESENT ⇒ submit the poison job (original + every pinned served size); on
 *       worker failure record {@code failed} + forward the ORIGINAL through (honest:
 *       no false "protected");</li>
 *   <li>do the REAL homeserver upload of the POISONED bytes via the mTLS proxy and
 *       capture the {@code media_id}/{@code mxc};</li>
 *   <li>ROUND-TRIP SURVIVAL GATE: re-fetch the served original + thumbnails and run the
 *       perturbation-presence check; persist {@code protected} ONLY if it survived, else
 *       {@code degraded};</li>
 *   <li>record the {@code media_poison_decision} row and return the homeserver response
 *       EXACTLY as the homeserver would (so the UI compose logic is untouched) + the
 *       server-owned status.</li>
 * </ol>
 *
 * <p>{@code mode=none} (opt-out) and a disabled feature forward straight through with
 * {@code status=none}. The expensive cloak only ever runs server-side, pre-ingest.
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

    /** The result the controller returns to the UI: the homeserver response verbatim +
     *  the server-owned decision. */
    public record UploadOutcome(Map<String, Object> homeserver, MediaPoisonDecision decision) {}

    /**
     * Poison-then-forward (or forward-through) one upload. {@code owner} is the JWT
     * subject (never a body field). {@code requestedMode} is the UI's choice; the
     * service resolves the effective mode + honest status server-side.
     */
    /** Back-compat overload — stamps/operates on the platform {@code default} domain. */
    public Mono<UploadOutcome> upload(String owner, String platform, String requestedMode,
                                      byte[] bytes, String filename, String declaredContentType) {
        return upload(owner, platform, requestedMode, bytes, filename, declaredContentType,
                DomainRegistry.DEFAULT_DOMAIN);
    }

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
                : (declaredContentType == null ? "application/octet-stream" : declaredContentType);

        // Opt-out / feature-off / non-image ⇒ forward through UNCHANGED, status=none.
        if ("none".equals(mode) || !props.isEnabled() || !isImage) {
            String why = !isImage ? "non-image" : ("none".equals(mode) ? "opt-out" : "feature-off");
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

    /**
     * The lean fallback when the heavy tier is absent. Default {@code skip}: forward the
     * ORIGINAL through with {@code status=skipped} (UI warns "not cloaked"). {@code light}/
     * {@code queue} also forward-through here (the light-CPU/queue paths attach to a
     * present worker; an ABSENT worker can do neither) — but the configured intent is
     * recorded so telemetry distinguishes the gap.
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
     * Poison the bytes (original + every pinned size), upload the POISONED original via
     * the mTLS proxy, then run the survival gate. On worker failure: record {@code failed}
     * and forward the ORIGINAL through (never a false "protected").
     */
    private Mono<UploadOutcome> cloakThenForward(String owner, String platform, String mode,
                                                 Backend probed, byte[] bytes, String filename,
                                                 String contentType, String domain) {
        return worker.poison(bytes, mode, filename, contentType, props.getThumbnailSizes())
                .flatMap(result -> {
                    if (result == null || !result.ok() || result.poisonedOriginal() == null) {
                        log.warn("[media] worker poison failed/empty ⇒ forward original, status=failed");
                        return forwardThrough(owner, platform, mode, "failed",
                                backendOf(result, probed), bytes, filename, contentType, domain);
                    }
                    Backend ran = Backend.parse(result.backend());
                    Backend backend = ran.present() ? ran : probed;
                    byte[] poisoned = result.poisonedOriginal();
                    return homeserver.upload(platform, poisoned, filename, contentType)
                            .flatMap(hs -> survivalGate(platform, mode, poisoned, result, hs)
                                    .flatMap(survived -> record(owner, platform, mediaRef(platform, hs),
                                            mode, survived ? "protected" : "degraded", backend.wire(), domain)
                                            .map(dec -> new UploadOutcome(hs, dec))));
                })
                // poison() emitted empty (no worker wired despite a present probe) ⇒ skip
                // honestly. DEFERRED so the forward-through upload only runs on the empty
                // path (not eagerly at assembly time).
                .switchIfEmpty(Mono.defer(() -> forwardThrough(owner, platform, mode, "skipped",
                        probed.wire(), bytes, filename, contentType, domain)));
    }

    /**
     * The ROUND-TRIP SURVIVAL GATE. Re-fetch the served original + each thumbnail size
     * and run the perturbation-presence check; the cloak counts as surviving ONLY if
     * the original AND every re-fetched thumbnail still carry it. A thumbnail we could
     * not re-fetch is treated as not-surviving (fail-honest). If the homeserver response
     * exposes no re-fetchable served URLs, fall back to checking the poisoned-original we
     * just uploaded (still a real perturbation check, just not post-transcode) so the gate
     * never silently passes.
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

    /** Back-compat overload — scopes to the platform {@code default} domain. */
    public Mono<MediaPoisonDecision> status(String owner, String mediaRef) {
        return status(owner, mediaRef, DomainRegistry.DEFAULT_DOMAIN);
    }

    /** The caller's most-recent decision for a media ref (badge poll), owner-AND-domain
     *  scoped ({@code domain} null = SUPERADMIN cross-domain bypass). */
    public Mono<MediaPoisonDecision> status(String owner, String mediaRef, String domain) {
        requireOwner(owner);
        return repo.findByOwnerAndRef(owner, mediaRef, domain)
                .switchIfEmpty(Mono.error(ApiException.notFound("no decision for this media")));
    }

    // ── helpers ────────────────────────────────────────────────────────────

    private static String backendOf(PoisonResult r, Backend probed) {
        Backend b = r == null ? Backend.NONE : Backend.parse(r.backend());
        return (b.present() ? b : probed).wire();
    }

    /** Extract the homeserver media ref EXACTLY as the homeserver returns it. */
    static String mediaRef(String platform, Map<String, Object> hs) {
        if (hs == null) return null;
        if ("matrix".equals(platform)) {
            Object uri = hs.get("content_uri");
            return uri == null ? null : uri.toString();
        }
        Object id = hs.get("id");
        return id == null ? null : id.toString();
    }

    /** The re-fetchable served URLs from the homeserver response (akkoma url + preview_url;
     *  Matrix derives a download path from the mxc). */
    static List<String> servedUrls(String platform, Map<String, Object> hs) {
        java.util.ArrayList<String> out = new java.util.ArrayList<>();
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
