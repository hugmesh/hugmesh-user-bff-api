package systems.snapdragon.userbff.media;

import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.snapdragon.commons.security.DomainRegistry;
import systems.snapdragon.commons.tenancy.DomainScope;

import java.util.UUID;

/**
 * Owner-AND-domain-scoped facade over {@link MediaPoisonDecisionR2dbcRepository} for
 * {@code media_poison_decision}. Keeps the original method surface ({@code record} /
 * {@code listForOwner} / {@code findByOwnerAndRef}, with the {@code default}-domain
 * back-compat overloads) so the media service and slice tests are unchanged; all data
 * access now flows through the reactive repository interface (no raw
 * {@code DatabaseClient SQL}).
 */
@Repository
public class MediaPoisonDecisionRepository {

    private final MediaPoisonDecisionR2dbcRepository repo;

    public MediaPoisonDecisionRepository(MediaPoisonDecisionR2dbcRepository repo) {
        this.repo = repo;
    }

    private static MediaPoisonDecision toWire(MediaPoisonDecisionEntity e) {
        return new MediaPoisonDecision(
                e.id(), e.userId(), e.platform(), e.mediaRef(), e.mode(), e.status(),
                e.backend(), e.createdAt());
    }

    /** Back-compat overload — stamps the platform {@code default} domain. */
    public Mono<MediaPoisonDecision> record(String userId, String platform, String mediaRef,
                                            String mode, String status, String backend) {
        return record(userId, platform, mediaRef, mode, status, backend, DomainRegistry.DEFAULT_DOMAIN);
    }

    /**
     * Record a decision for the owner (app-generated id) and return it. The
     * {@code mediaRef} is nullable (a pre-upload failure has no homeserver ref yet);
     * {@code backend} is nullable (no worker ran). The owner is the JWT subject the
     * service passes — never a request field.
     */
    public Mono<MediaPoisonDecision> record(String userId, String platform, String mediaRef,
                                            String mode, String status, String backend, String domain) {
        String id = UUID.randomUUID().toString();
        String dom = DomainScope.isUnscoped(domain) ? DomainRegistry.DEFAULT_DOMAIN : domain;
        return repo.insertRow(id, userId, platform, mediaRef, mode, status, backend, dom)
                .then(repo.findById(id))
                .map(MediaPoisonDecisionRepository::toWire);
    }

    /** Back-compat overload — scopes to the platform {@code default} domain. */
    public Flux<MediaPoisonDecision> listForOwner(String userId) {
        return listForOwner(userId, DomainRegistry.DEFAULT_DOMAIN);
    }

    /** Back-compat overload — scopes to the platform {@code default} domain. */
    public Mono<MediaPoisonDecision> findByOwnerAndRef(String userId, String mediaRef) {
        return findByOwnerAndRef(userId, mediaRef, DomainRegistry.DEFAULT_DOMAIN);
    }

    /** All of the owner's decisions in their domain (own data only), newest first
     *  ({@code domain} null = SUPERADMIN cross-domain bypass). */
    public Flux<MediaPoisonDecision> listForOwner(String userId, String domain) {
        var rows = DomainScope.isUnscoped(domain)
                ? repo.findByUserIdOrderByCreatedAtDescIdAsc(userId)
                : repo.findByUserIdAndDomainOrderByCreatedAtDescIdAsc(userId, domain);
        return rows.map(MediaPoisonDecisionRepository::toWire);
    }

    /**
     * The owner's most-recent decision for a {@code media_ref} in their domain (the
     * badge poll + already-cloaked repost guard). Owner-AND-domain-AND-ref scoped so a
     * caller can never read another user's (or brand's) decision even with a known ref.
     */
    public Mono<MediaPoisonDecision> findByOwnerAndRef(String userId, String mediaRef, String domain) {
        var found = DomainScope.isUnscoped(domain)
                ? repo.findFirstByUserIdAndMediaRefOrderByCreatedAtDescIdAsc(userId, mediaRef)
                : repo.findFirstByUserIdAndMediaRefAndDomainOrderByCreatedAtDescIdAsc(userId, mediaRef, domain);
        return found.map(MediaPoisonDecisionRepository::toWire);
    }
}
