package systems.snapdragon.userbff.character;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.snapdragon.commons.web.ApiException;
import systems.snapdragon.userbff.federation.FederationApiClient;
import systems.snapdragon.userbff.federation.FederationModerationModels.FindingRequest;
import systems.snapdragon.userbff.svg.SvgSanitizerService;

/**
 * Owner-enforced save of a USER-DRAWN character PART (an SVG). The leg is
 * SANITIZE → STORE-PENDING → FILE-MODERATION-FINDING:
 * <ol>
 *   <li>{@link SvgSanitizerService#sanitize(String)} allowlist-filters the dirty client
 *       SVG to a safe subset — the AUTHORITATIVE stored-XSS boundary, run BEFORE
 *       anything is persisted. It FAILS CLOSED on null/blank/malformed/non-svg-root by
 *       throwing {@code SvgSanitizerService.InvalidSvgException}; we map that to a 422
 *       ({@link ApiException#unprocessable(String)}). There is deliberately NO
 *       server-side rasterizer — the moderator reviews the SANITIZED SVG itself;</li>
 *   <li>persist the SANITIZED svg via {@link VnCharacterPartRepository} owner AND domain
 *       scoped, {@code status='PENDING'} (the row enters the moderation queue);</li>
 *   <li>file a held {@code @system} moderation finding (A3 producer, surface=
 *       {@code character-part}, disposition={@code flagged}) so a HUMAN reviews the part.
 *       BEST-EFFORT (mirrors {@code AvatarService.fileHeldFinding}): a federation outage
 *       is logged and swallowed — it must NEVER fail the user's save (the part is stored
 *       PENDING regardless and a moderator can still find it).</li>
 * </ol>
 *
 * <p>{@code owner} is the caller's JWT subject (passed by the controller from the
 * validated token) — a user can only ever save/list/serve their OWN parts. The SVG is
 * never logged.
 */
@Service
public class CharacterPartService {

    private static final Logger log = LoggerFactory.getLogger(CharacterPartService.class);

    /** Newly-saved parts land here, awaiting human moderation of the sanitized SVG. */
    private static final String STATUS_PENDING = "PENDING";

    /** Federation finding surface for a user-drawn character part. */
    private static final String FINDING_SURFACE = "character-part";

    /** A saved part is queued for human review (never auto-rejected here). */
    private static final String FINDING_DISPOSITION = "flagged";

    private final SvgSanitizerService sanitizer;
    private final VnCharacterPartRepository repo;
    private final FederationApiClient federation;

    public CharacterPartService(SvgSanitizerService sanitizer, VnCharacterPartRepository repo,
                                FederationApiClient federation) {
        this.sanitizer = sanitizer;
        this.repo = repo;
        this.federation = federation;
    }

    /**
     * Sanitize, store PENDING, and file a held moderation finding for a user-drawn part.
     *
     * @param owner         the caller's JWT subject (the owner row key); must be non-blank.
     * @param domain        the caller's validated-issuer brand ({@code null} = SUPERADMIN
     *                      cross-domain bypass).
     * @param name          the user's label for the part (nullable).
     * @param headArchetype the head archetype the part is drawn for (nullable).
     * @param dirtySvg      the raw client SVG (never logged; sanitized before storage).
     * @return the stored part (status PENDING).
     * @throws IllegalArgumentException if {@code owner} is null/blank.
     * @throws ApiException 422 when the SVG is null/blank/malformed/not a {@code <svg>}.
     */
    public Mono<VnCharacterPart> savePart(String owner, String domain, String name,
                                          String headArchetype, String dirtySvg) {
        if (owner == null || owner.isBlank()) {
            throw new IllegalArgumentException("owner (JWT subject) is required");
        }
        // Deferred so the synchronous sanitize step (and its fail-closed 422) is delivered
        // as a reactive error on subscribe — the WebFlux-idiomatic surfacing of the 422.
        return Mono.defer(() -> {
            // 1) AUTHORITATIVE sanitize BEFORE storage. The sanitizer fails closed on bad
            //    input (InvalidSvgException) — we never echo unparseable input back and we
            //    never persist raw client XML. Map the fail-closed exception to a clean 422.
            String safeSvg = sanitizeOr422(dirtySvg);
            // 2) persist the SANITIZED svg, status=PENDING (owner + domain scoped), then
            // 3) best-effort file the held @system finding so a moderator reviews the part.
            //    The finding-file is fail-soft — a federation outage must not fail the save.
            return repo.save(owner, domain, name, safeSvg, STATUS_PENDING, headArchetype)
                    .flatMap(part -> fileHeldFinding(owner).thenReturn(part));
        });
    }

    /** All of the caller's parts in their domain, newest first (own data only). */
    public Flux<VnCharacterPart> listMine(String owner, String domain) {
        return repo.listForOwner(owner, domain);
    }

    /**
     * The caller's single part by id (the serve path), owner-scoped. A foreign id yields
     * empty — the controller maps that to a 404 (not a 403), so cross-owner existence is
     * never leaked.
     */
    public Mono<VnCharacterPart> getOwned(String id, String owner) {
        return repo.findOwned(id, owner);
    }

    /** Sanitize the SVG; map the sanitizer's fail-closed {@code InvalidSvgException} to a
     *  422 so a malformed/non-svg part is an UNPROCESSABLE-ENTITY, never a 500. */
    private String sanitizeOr422(String dirtySvg) {
        try {
            return sanitizer.sanitize(dirtySvg);
        } catch (SvgSanitizerService.InvalidSvgException e) {
            throw ApiException.unprocessable("character part is not a valid SVG: " + e.getMessage());
        }
    }

    /**
     * File the saved part into the federation {@code @system} findings queue (held, for
     * moderator review). The caller's bearer is forwarded by {@link FederationApiClient},
     * so federation derives {@code subject} = owner (a user only files about their OWN
     * content) and stamps {@code reporter="@system"} + {@code status="held"} server-side.
     * Fail-soft: a federation error is logged and swallowed (the part is stored PENDING
     * either way). {@code surface="character-part"}, {@code disposition="flagged"} (queued
     * for human review); the edge-AI verdict fields are absent (a part is reviewed by a
     * human reading the sanitized SVG — no server-side classifier ran).
     */
    private Mono<Void> fileHeldFinding(String owner) {
        FindingRequest req = new FindingRequest(
                FINDING_SURFACE, FINDING_DISPOSITION, null, null, null, null);
        return federation.fileFinding(req)
                .doOnNext(r -> log.info("[character-part] finding filed (held) for owner={} disposition={}",
                        owner, FINDING_DISPOSITION))
                .onErrorResume(e -> {
                    log.warn("[character-part] finding-file FAILED (part still stored PENDING) owner={}: {}",
                            owner, e.toString());
                    return Mono.empty();
                })
                .then();
    }
}
