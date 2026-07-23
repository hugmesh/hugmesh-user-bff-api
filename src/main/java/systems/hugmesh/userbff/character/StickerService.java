package systems.hugmesh.userbff.character;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.hugmesh.commons.web.ApiException;
import systems.hugmesh.userbff.federation.FederationApiClient;
import systems.hugmesh.userbff.federation.FederationModerationModels.FindingRequest;
import systems.hugmesh.userbff.profile.EdgeAiAnalysisClient;
import systems.hugmesh.userbff.profile.MatrixMediaClient;
import systems.hugmesh.userbff.profile.ModerationVerdict;

/**
 * Owner-enforced save of a VN-CHARACTER EXPRESSION STICKER — a raster (PNG) snapshot the
 * character rig renders at a canonical {@link StickerExpression} (the same way the avatar
 * is an uploaded raster). The leg is MODERATE → UPLOAD → STORE-PENDING →
 * FILE-MODERATION-FINDING and DELIBERATELY REUSES the avatar seam:
 * <ol>
 *   <li>edge-AI vision-moderate the PNG bytes BEFORE anything is published
 *       ({@link EdgeAiAnalysisClient#moderate(byte[])}): dark-by-default ⇒ allow;
 *       FAIL-CLOSED ({@code reject}) when enabled-but-unreachable. A
 *       {@link ModerationVerdict#blocks() blocked} sticker NEVER reaches the homeserver
 *       and is NEVER persisted — it files a held {@code @system} finding
 *       (disposition reject→{@code rejected} / flag→{@code flagged}) then surfaces a 422.
 *       (Mirrors {@code AvatarService.uploadAndStore} exactly.);</li>
 *   <li>an ALLOWED sticker's bytes are uploaded to the homeserver media repo via
 *       {@link MatrixMediaClient} (STUB-GATED — a stub {@code mxc://} when the live upload
 *       ships dark) → {@code mxc://} URL;</li>
 *   <li>persist the {@code mxc://} via {@link VnStickerRepository} owner AND domain scoped,
 *       {@code status='PENDING'} (the row enters the moderation queue);</li>
 *   <li>file a held {@code @system} moderation finding (A3 producer, surface=
 *       {@code character-sticker}, disposition={@code flagged}) so a HUMAN reviews the
 *       sticker. BEST-EFFORT (mirrors {@code AvatarService.fileHeldFinding}): a federation
 *       outage is logged and swallowed — it must NEVER fail the user's save (the sticker
 *       is stored PENDING regardless and a moderator can still find it).</li>
 * </ol>
 *
 * <p>{@code owner} is the caller's JWT subject (passed by the controller from the
 * validated token) — a user can only ever save/list their OWN stickers. The PNG bytes are
 * never logged.
 */
@Service
public class StickerService {

    private static final Logger log = LoggerFactory.getLogger(StickerService.class);

    /** Newly-saved (moderated-passed) stickers land here, awaiting human moderation. */
    private static final String STATUS_PENDING = "PENDING";

    /** Federation finding surface for a VN-character expression sticker. */
    private static final String FINDING_SURFACE = "character-sticker";

    /** A saved sticker is queued for human review (never auto-approved here). */
    private static final String FINDING_DISPOSITION_FLAGGED = "flagged";

    private final EdgeAiAnalysisClient moderation;
    private final MatrixMediaClient matrixMedia;
    private final VnStickerRepository repo;
    private final FederationApiClient federation;

    public StickerService(EdgeAiAnalysisClient moderation, MatrixMediaClient matrixMedia,
                          VnStickerRepository repo, FederationApiClient federation) {
        this.moderation = moderation;
        this.matrixMedia = matrixMedia;
        this.repo = repo;
        this.federation = federation;
    }

    /**
     * Moderate, upload, store PENDING, and file a held moderation finding for one
     * expression sticker.
     *
     * @param owner       the caller's JWT subject (the owner row key); must be non-blank.
     * @param domain      the caller's validated-issuer brand ({@code null} = SUPERADMIN
     *                    cross-domain bypass).
     * @param expression  the canonical expression label (validated against
     *                    {@link StickerExpression#ALL}; a 422 otherwise).
     * @param bytes       the raw PNG bytes (never logged; moderated before upload).
     * @param contentType the image MIME type (the magic-byte-sniffed type from the
     *                    controller — never the client header).
     * @return the stored sticker (status PENDING) on a passing verdict.
     * @throws IllegalArgumentException if {@code owner} is null/blank.
     * @throws ApiException 422 when the expression is not canonical, or when the verdict
     *                      blocks the sticker.
     */
    public Mono<VnSticker> save(String owner, String domain, String expression,
                                byte[] bytes, String contentType) {
        if (owner == null || owner.isBlank()) {
            throw new IllegalArgumentException("owner (JWT subject) is required");
        }
        if (!StickerExpression.isValid(expression)) {
            // Surface as a reactive 422 (consistent with the moderation-block 422 below),
            // not a thrown IllegalArgumentException, so the controller path is uniform.
            return Mono.error(ApiException.unprocessable(
                    "expression must be one of the canonical expressions: " + StickerExpression.ALL));
        }
        // 0) edge-AI vision moderation BEFORE publish (dark by default ⇒ allow; FAIL-CLOSED
        //    when enabled-but-unreachable). A blocked sticker never reaches the homeserver
        //    and is never persisted. Bytes are never logged — only the policy verdict.
        // 1) upload to the homeserver media repo (stub-gated) -> mxc:// URL;
        // 2) persist the mxc:// + expression, status=PENDING (owner + domain scoped);
        // 3) best-effort file the held @system finding so a moderator reviews the sticker.
        return moderation.moderate(bytes).flatMap(verdict -> {
            if (verdict.blocks()) {
                log.info("[sticker] BLOCKED by content policy: action={} class={} confidence={} "
                                + "owner={} expression={}",
                        verdict.action(), verdict.classification(), verdict.confidence(), owner, expression);
                // A3 producer: file the blocked sticker into the federation @system findings
                // queue (held). BEST-EFFORT — the sticker is blocked regardless; a federation
                // outage must not change the 422, so a file failure is logged and swallowed.
                return fileBlockedFinding(owner, verdict)
                        .then(Mono.<VnSticker>error(ApiException.unprocessable(
                                "character sticker blocked by content policy")));
            }
            return matrixMedia.upload(owner, bytes, contentType)
                    .flatMap(mxc -> repo.save(owner, domain, expression, mxc, STATUS_PENDING))
                    .flatMap(sticker -> captureFinding(owner, sticker).thenReturn(sticker));
        });
    }

    /** All of the caller's stickers in their domain, newest first (own data only). */
    public Flux<VnSticker> listMine(String owner, String domain) {
        return repo.listForOwner(owner, domain);
    }

    /**
     * The caller's single sticker by id, owner-scoped. A foreign id yields empty — the
     * controller maps that to a 404 (not a 403), so cross-owner existence is never leaked.
     */
    public Mono<VnSticker> getOwned(String id, String owner) {
        return repo.findOwned(id, owner);
    }

    /**
     * File a BLOCKED sticker verdict into the federation {@code @system} findings queue
     * (held, for moderator review). Fail-soft: a federation error is logged and swallowed
     * (the sticker stays blocked either way). The edge-AI {@code action} ({@code flag} |
     * {@code reject}) maps to the federation {@code disposition} ({@code flagged} |
     * {@code rejected}); {@code surface="character-sticker"}. Mirrors
     * {@code AvatarService.fileHeldFinding}.
     */
    private Mono<Void> fileBlockedFinding(String owner, ModerationVerdict verdict) {
        String disposition = "reject".equalsIgnoreCase(verdict.action()) ? "rejected" : FINDING_DISPOSITION_FLAGGED;
        // subjectRef=null: a BLOCKED sticker is NEVER persisted, so there is no row id to
        // back-link the finding to (the finding stands alone for moderator context).
        FindingRequest req = new FindingRequest(
                FINDING_SURFACE, disposition, verdict.classification(),
                verdict.confidence(), verdict.policyHit(), verdict.perceptualHash(), null);
        return federation.fileFinding(req)
                .doOnNext(r -> log.info("[sticker] finding filed (held, blocked) for owner={} disposition={}",
                        owner, disposition))
                .onErrorResume(e -> {
                    log.warn("[sticker] finding-file FAILED (sticker still blocked) owner={}: {}",
                            owner, e.toString());
                    return Mono.empty();
                })
                .then();
    }

    /**
     * CAPTURE-AT-FILE: file the saved (moderated-passed) sticker into the federation
     * {@code @system} findings queue (held, for moderator review) AND write the returned
     * finding id back onto the row's {@code finding_id} (the back-link the moderation
     * receiver flips on). The caller's bearer is forwarded by {@link FederationApiClient},
     * so federation derives {@code subject} = owner and stamps {@code reporter="@system"} +
     * {@code status="held"} server-side. The just-saved {@code sticker.id()} is passed as
     * the finding {@code subjectRef} (the producer-side back-reference federation-api #70
     * echoes back).
     *
     * <p>Fail-soft end-to-end: a federation error — or a response with no usable finding
     * id — is logged and swallowed (the sticker is stored PENDING either way; only the
     * convenience back-link is lost). {@code surface="character-sticker"},
     * {@code disposition="flagged"} (queued for human review); the edge-AI verdict fields
     * are absent (the bytes passed the auto-classifier — a human reviews the rendered
     * sticker).
     */
    private Mono<Void> captureFinding(String owner, VnSticker sticker) {
        FindingRequest req = new FindingRequest(
                FINDING_SURFACE, FINDING_DISPOSITION_FLAGGED, null, null, null, null, sticker.id());
        return federation.fileFinding(req)
                .flatMap(resp -> stampFindingId(owner, sticker.id(), resp))
                .onErrorResume(e -> {
                    log.warn("[sticker] finding-capture FAILED (sticker still stored PENDING) owner={}: {}",
                            owner, e.toString());
                    return Mono.empty();
                })
                .then();
    }

    /**
     * Read the federation finding id back from the {@code fileFinding} response Map and
     * stamp it onto the owner's row ({@code finding_id}). A missing/non-numeric id leaves
     * the row's back-link null (still a valid PENDING row a moderator resolves by id). The
     * write-back is owner-scoped at the repo.
     */
    private Mono<Integer> stampFindingId(String owner, String rowId, java.util.Map<String, Object> resp) {
        Long findingId = FindingIdParser.parse(resp == null ? null : resp.get("id"));
        if (findingId == null) {
            log.info("[sticker] finding filed (held) for owner={} disposition={} (no finding id in response)",
                    owner, FINDING_DISPOSITION_FLAGGED);
            return Mono.just(0);
        }
        log.info("[sticker] finding filed (held) id={} for owner={} disposition={}",
                findingId, owner, FINDING_DISPOSITION_FLAGGED);
        return repo.setFindingId(rowId, owner, findingId);
    }
}
