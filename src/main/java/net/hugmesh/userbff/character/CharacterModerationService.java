package net.hugmesh.userbff.character;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import net.hugmesh.commons.web.ApiException;

import java.util.Set;
import java.util.function.Supplier;

/**
 * The RECEIVING half of the part/sticker ACTIVATION loop: flip a moderated row's
 * {@code status} from {@code PENDING} to {@code ACTIVE} or {@code REJECTED} when a
 * moderator resolves the {@code @system} finding the row filed at save time.
 *
 * <p>SEMANTICS (confirmed): a finding resolved {@code actioned=true} ⇒ the moderator
 * CONFIRMED the content is bad ⇒ {@code REJECTED}; a finding {@code dismissed}
 * ({@code actioned=false}) ⇒ the moderator CLEARED it ⇒ {@code ACTIVE}. This service
 * receives the already-resolved target status (the admin-bff reconciler — a LATER PR —
 * does that mapping and calls the SERVICE-gated internal endpoint); here we only enforce
 * that the target is one of {@code {ACTIVE, REJECTED}} and apply the PENDING-guarded flip.
 *
 * <p>IDEMPOTENT by construction: the flip is {@code WHERE status='PENDING'}, so a second
 * resolve of the same finding, or a resolve targeting an already-{@code ACTIVE}/{@code
 * REJECTED}/unknown row, updates ZERO rows — a safe no-op the receiver surfaces as a 404
 * (nothing-flipped). On a successful flip (1 row) the post-flip row is returned so the
 * caller sees the new status.
 *
 * <p>This is FORK-FREE and SELF-CONTAINED: it consults no external service (the finding's
 * resolution already happened upstream); it only mutates the local moderated-row state.
 */
@Service
public class CharacterModerationService {

    private static final Logger log = LoggerFactory.getLogger(CharacterModerationService.class);

    /** The only two terminal statuses a resolve may flip a PENDING row to. */
    public static final String STATUS_ACTIVE = "ACTIVE";
    public static final String STATUS_REJECTED = "REJECTED";
    private static final Set<String> TERMINAL = Set.of(STATUS_ACTIVE, STATUS_REJECTED);

    private final VnCharacterPartRepository partRepo;
    private final VnStickerRepository stickerRepo;
    /** MSC2545 pack registrar — hooked onto a SUCCESSFUL sticker→ACTIVE flip (dark by default). */
    private final StickerPackRegistrationService packRegistration;

    public CharacterModerationService(VnCharacterPartRepository partRepo,
                                      VnStickerRepository stickerRepo,
                                      StickerPackRegistrationService packRegistration) {
        this.partRepo = partRepo;
        this.stickerRepo = stickerRepo;
        this.packRegistration = packRegistration;
    }

    /**
     * Flip a PENDING character PART to the resolved terminal {@code status}.
     *
     * @param id       the part row id (the finding's {@code subjectRef}).
     * @param status   the resolved target status — must be {@code ACTIVE} or {@code REJECTED}.
     * @param findingId the resolved federation finding id (audit only — logged, not gated on).
     * @param reviewer the resolving moderator (audit only — logged, not stored).
     * @return the post-flip part on a 1-row flip; EMPTY on a no-op (unknown / already-resolved).
     * @throws ApiException 400 when {@code status} is not a terminal status.
     */
    public Mono<VnCharacterPart> resolvePart(String id, String status, Long findingId, String reviewer) {
        return flip(() -> partRepo.updateStatusByIdWherePending(id, requireTerminal(status)),
                () -> partRepo.findAnyById(id), "part", id, status, findingId, reviewer);
    }

    /**
     * Flip a PENDING expression STICKER to the resolved terminal {@code status}.
     *
     * @param id       the sticker row id (the finding's {@code subjectRef}).
     * @param status   the resolved target status — must be {@code ACTIVE} or {@code REJECTED}.
     * @param findingId the resolved federation finding id (audit only).
     * @param reviewer the resolving moderator (audit only).
     * @return the post-flip sticker on a 1-row flip; EMPTY on a no-op.
     * @throws ApiException 400 when {@code status} is not a terminal status.
     */
    public Mono<VnSticker> resolveSticker(String id, String status, Long findingId, String reviewer) {
        return flip(() -> stickerRepo.updateStatusByIdWherePending(id, requireTerminal(status)),
                () -> stickerRepo.findAnyById(id), "sticker", id, status, findingId, reviewer)
                // Only a SUCCESSFUL flip emits a row (a no-op completes empty, so this never
                // runs for unknown / already-resolved ids). Register the owner's MSC2545 pack
                // ONLY when the target was ACTIVE — never for REJECTED.
                .flatMap(flipped -> STATUS_ACTIVE.equals(status)
                        ? registerPackThenReturn(flipped)
                        : Mono.just(flipped));
    }

    /**
     * FAIL-SOFT side-effect: upsert the owner's ACTIVE stickers into their Matrix MSC2545
     * pack, then return the post-flip sticker REGARDLESS of the registration outcome. The
     * registrar already swallows its own errors (returning empty), but we also guard here
     * with {@code onErrorResume} so a registration failure can NEVER fail the moderator's
     * flip. {@code thenReturn} re-emits the sticker after the (empty) registration completes.
     */
    private Mono<VnSticker> registerPackThenReturn(VnSticker flipped) {
        return packRegistration.registerActivePack(flipped.ownerSubject())
                .onErrorResume(e -> {
                    log.warn("[character-moderation] sticker pack registration failed for owner={} "
                            + "(swallowed — flip unaffected): {}", flipped.ownerSubject(), e.toString());
                    return Mono.empty();
                })
                .thenReturn(flipped);
    }

    /**
     * Shared flip mechanic: run the PENDING-guarded update, then re-read on success; on a
     * 0-row no-op return EMPTY (the receiver maps that to a 404). {@code requireTerminal}
     * runs INSIDE the update supplier so the 400 surfaces reactively before any DB write.
     */
    private <T> Mono<T> flip(Supplier<Mono<Integer>> update,
                             Supplier<Mono<T>> reread,
                             String kind, String id, String status, Long findingId, String reviewer) {
        return Mono.defer(update)
                .flatMap(rows -> afterFlip(rows, reread, kind, id, status, findingId, reviewer));
    }

    /** The {@link #flip} leg after the update: re-read on a flipped row, EMPTY on a no-op. */
    private <T> Mono<T> afterFlip(Integer rows, Supplier<Mono<T>> reread,
                                  String kind, String id, String status, Long findingId, String reviewer) {
        if (rows != null && rows > 0) {
            log.info("[character-moderation] {} id={} flipped to {} (findingId={}, reviewer={})",
                    kind, id, status, findingId, reviewer);
            return reread.get();
        }
        // 0 rows: unknown id OR already-resolved (not PENDING). Idempotent no-op.
        log.info("[character-moderation] {} id={} NO-OP (not PENDING / unknown) "
                        + "target={} findingId={} reviewer={}",
                kind, id, status, findingId, reviewer);
        return Mono.empty();
    }

    /** Enforce the resolved status is one of the two terminal flips; a 400 otherwise. */
    private static String requireTerminal(String status) {
        if (status == null || !TERMINAL.contains(status)) {
            throw ApiException.badRequest(
                    "status must be one of " + TERMINAL + " (the resolved moderation outcome)");
        }
        return status;
    }
}
