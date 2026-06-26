package systems.snapdragon.userbff.character;

import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.snapdragon.commons.security.DomainRegistry;
import systems.snapdragon.commons.tenancy.DomainScope;

/**
 * Owner-AND-domain-scoped facade over {@link VnStickerR2dbcRepository} for
 * {@code vn_sticker_pack}. Mirrors {@link VnCharacterPartRepository}: all data access
 * flows through the reactive repository interface (no raw SQL); the {@code save} does an
 * INSERT ... RETURNING id then a read-back to return the persisted wire shape;
 * {@code listForOwner}/{@code findOwned} are owner-AND-domain scoped so a caller can
 * never read another user's (or brand's) sticker.
 *
 * <p>A {@code null}/unscoped {@code domain} is the SUPERADMIN cross-domain bypass; an
 * unscoped SAVE stamps {@link DomainRegistry#DEFAULT_DOMAIN}.
 */
@Repository
public class VnStickerRepository {

    private final VnStickerR2dbcRepository repo;

    public VnStickerRepository(VnStickerR2dbcRepository repo) {
        this.repo = repo;
    }

    private static VnSticker toWire(VnStickerEntity e) {
        return new VnSticker(
                e.id(), e.ownerSubject(), e.domain(), e.expression(), e.mxcUrl(),
                e.status(), e.findingId(), e.createdAt());
    }

    /**
     * Persist a sticker for the owner (app-omits id; the DB generates it) and return it.
     * The {@code mxcUrl} is the homeserver media-upload result (the service uploads before
     * calling here). The owner is the JWT subject the service passes — never a request
     * field. The {@code expression} is a canonical {@link StickerExpression} label;
     * {@code status} is the caller-supplied lifecycle literal ({@code PENDING} on save).
     */
    public Mono<VnSticker> save(String ownerSubject, String domain, String expression,
                                String mxcUrl, String status) {
        String dom = DomainScope.isUnscoped(domain) ? DomainRegistry.DEFAULT_DOMAIN : domain;
        // The id is DB-generated (changelog 017 column DEFAULT): the INSERT omits it and
        // RETURNING id hands back the generated UUID string, which drives the read-back.
        return repo.insertRowReturningId(ownerSubject, dom, expression, mxcUrl, status)
                .flatMap(repo::findById)
                .map(VnStickerRepository::toWire);
    }

    /** All of the owner's stickers in their domain (own data only), newest first
     *  ({@code domain} null = SUPERADMIN cross-domain bypass). */
    public Flux<VnSticker> listForOwner(String ownerSubject, String domain) {
        var rows = DomainScope.isUnscoped(domain)
                ? repo.findByOwnerSubjectOrderByCreatedAtDesc(ownerSubject)
                : repo.findByOwnerSubjectAndDomainOrderByCreatedAtDesc(ownerSubject, domain);
        return rows.map(VnStickerRepository::toWire);
    }

    /**
     * The owner's ACTIVE stickers ACROSS all domains, newest first — the source set the
     * MSC2545 pack-registration service advertises in the owner's {@code
     * im.ponies.user_emotes} account-data. NOT domain-scoped: a Matrix account-data pack is
     * per homeserver USER (one Matrix identity per owner subject), so every approved sticker
     * the owner holds — regardless of which brand it was created under — belongs in their
     * single pack. Only {@code ACTIVE} (moderator-approved) rows are returned; PENDING /
     * REJECTED are excluded at the SQL layer.
     */
    public Flux<VnSticker> listActiveForOwner(String ownerSubject) {
        return repo.findByOwnerSubjectAndStatusOrderByCreatedAtDesc(
                        ownerSubject, CharacterModerationService.STATUS_ACTIVE)
                .map(VnStickerRepository::toWire);
    }

    /**
     * The owner's single sticker by id, owner-scoped at the SQL layer so a caller can never
     * read another user's sticker even with a known id — a foreign id yields empty (the
     * controller maps that to a 404, never a 403, so existence is not leaked). Owner-scoped
     * (not domain-scoped) because the read is keyed by the opaque UUID id the owner already
     * holds; a sticker is single-owner.
     */
    public Mono<VnSticker> findOwned(String id, String ownerSubject) {
        return repo.findByIdAndOwnerSubject(id, ownerSubject)
                .map(VnStickerRepository::toWire);
    }

    /**
     * CAPTURE-AT-FILE write-back: stamp the federation {@code @system} finding id onto the
     * caller's OWN just-saved row. Owner-scoped (defence-in-depth). Best-effort: the
     * service swallows a failure. Returns rows-affected (1 on the happy path). Mirrors
     * {@link VnCharacterPartRepository#setFindingId(String, String, Long)}.
     */
    public Mono<Integer> setFindingId(String id, String owner, Long findingId) {
        return repo.setFindingId(id, owner, findingId);
    }

    /**
     * STATUS FLIP (the moderation receiver): flip a {@code PENDING} sticker to
     * {@code ACTIVE} or {@code REJECTED}. PENDING-guarded + idempotent — a second resolve /
     * an unknown or already-resolved id updates ZERO rows. Returns rows-affected (1 =
     * flipped, 0 = no-op). The {@code status} is the controller-validated literal.
     */
    public Mono<Integer> updateStatusByIdWherePending(String id, String status) {
        return repo.updateStatusByIdWherePending(id, status);
    }

    /**
     * Read a sticker by id ACROSS owners (the SERVICE moderation receiver has no owner
     * context). Used ONLY to return the post-flip row to the SERVICE caller. Empty when
     * the id is unknown. Mirrors {@link VnCharacterPartRepository#findAnyById(String)}.
     */
    public Mono<VnSticker> findAnyById(String id) {
        return repo.findById(id).map(VnStickerRepository::toWire);
    }
}
