package systems.snapdragon.userbff.character;

import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.snapdragon.commons.security.DomainRegistry;
import systems.snapdragon.commons.tenancy.DomainScope;

/**
 * Owner-AND-domain-scoped facade over {@link VnCharacterPartR2dbcRepository} for
 * {@code vn_character_part}. Mirrors {@code MediaPoisonDecisionRepository}: all data
 * access flows through the reactive repository interface (no raw SQL); the {@code save}
 * does an INSERT ... RETURNING id then a read-back to return the persisted wire shape;
 * {@code listForOwner}/{@code findOwned} are owner-AND-domain scoped so a caller can
 * never read another user's (or brand's) part.
 *
 * <p>A {@code null}/unscoped {@code domain} is the SUPERADMIN cross-domain bypass; an
 * unscoped SAVE stamps {@link DomainRegistry#DEFAULT_DOMAIN}.
 */
@Repository
public class VnCharacterPartRepository {

    private final VnCharacterPartR2dbcRepository repo;

    public VnCharacterPartRepository(VnCharacterPartR2dbcRepository repo) {
        this.repo = repo;
    }

    private static VnCharacterPart toWire(VnCharacterPartEntity e) {
        return new VnCharacterPart(
                e.id(), e.ownerSubject(), e.domain(), e.name(), e.svg(), e.status(),
                e.headArchetype(), e.createdAt());
    }

    /**
     * Persist a part for the owner (app-omits id; the DB generates it) and return it.
     * The {@code svg} is ALREADY the sanitized subset (the service sanitizes before
     * calling here). The owner is the JWT subject the service passes — never a request
     * field. The {@code name}/{@code headArchetype} are nullable; {@code status} is the
     * caller-supplied lifecycle literal ({@code PENDING} on save).
     */
    public Mono<VnCharacterPart> save(String ownerSubject, String domain, String name,
                                      String svg, String status, String headArchetype) {
        String dom = DomainScope.isUnscoped(domain) ? DomainRegistry.DEFAULT_DOMAIN : domain;
        // The id is DB-generated (changelog 016 column DEFAULT): the INSERT omits it and
        // RETURNING id hands back the generated UUID string, which drives the read-back.
        return repo.insertRowReturningId(ownerSubject, dom, name, svg, status, headArchetype)
                .flatMap(repo::findById)
                .map(VnCharacterPartRepository::toWire);
    }

    /** All of the owner's parts in their domain (own data only), newest first
     *  ({@code domain} null = SUPERADMIN cross-domain bypass). */
    public Flux<VnCharacterPart> listForOwner(String ownerSubject, String domain) {
        var rows = DomainScope.isUnscoped(domain)
                ? repo.findByOwnerSubjectOrderByCreatedAtDesc(ownerSubject)
                : repo.findByOwnerSubjectAndDomainOrderByCreatedAtDesc(ownerSubject, domain);
        return rows.map(VnCharacterPartRepository::toWire);
    }

    /**
     * The owner's single part by id (the serve path). Owner-scoped at the SQL layer so a
     * caller can never read another user's part even with a known id — a foreign id
     * yields empty (the controller maps that to a 404, never a 403, so existence is not
     * leaked). NOTE: this is owner-scoped (not domain-scoped) because the serve path is
     * keyed by the opaque UUID id the owner already holds; a part is single-owner.
     */
    public Mono<VnCharacterPart> findOwned(String id, String ownerSubject) {
        return repo.findByIdAndOwnerSubject(id, ownerSubject)
                .map(VnCharacterPartRepository::toWire);
    }
}
