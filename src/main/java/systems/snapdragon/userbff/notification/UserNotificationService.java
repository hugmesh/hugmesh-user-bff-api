package systems.snapdragon.userbff.notification;

import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import systems.snapdragon.commons.security.DomainRegistry;
import systems.snapdragon.commons.web.ApiException;

import java.util.List;

/**
 * Owner-enforced read/mark-read side of the in-app notification FLOOR. EVERY method
 * takes the owner (the JWT subject) and operates ONLY on that owner's notifications in
 * that owner's domain — a user can never read or mark-read another user's (or brand's)
 * notification.
 *
 * <p>SHIPS DARK in PR1: there is no create path — the snapdragon-actions reconciler in
 * a later PR is the only writer. This service is the list + mark-read side. A mark-read
 * of an id that is not the caller's own owner+domain row is a clean 404 (no cross-user
 * mark), distinguishing "already-read own row" (idempotent success) from "not yours".
 */
@Service
public class UserNotificationService {

    private final UserNotificationRepository repo;

    public UserNotificationService(UserNotificationRepository repo) {
        this.repo = repo;
    }

    /** Back-compat overload — scopes to the platform {@code default} domain. */
    public Mono<List<UserNotification>> list(String owner, int limit) {
        return list(owner, DomainRegistry.DEFAULT_DOMAIN, limit);
    }

    /**
     * The owner's in-app notifications in their domain (own data only), newest first,
     * server-capped (the repo clamps the limit into {@code [1, MAX_PAGE]}).
     * {@code domain} null = SUPERADMIN cross-domain bypass.
     */
    public Mono<List<UserNotification>> list(String owner, String domain, int limit) {
        requireOwner(owner);
        return repo.listForOwner(owner, domain, limit).collectList();
    }

    /** Back-compat overload — operates on the platform {@code default} domain. */
    public Mono<Void> markRead(String id, String owner) {
        return markRead(id, owner, DomainRegistry.DEFAULT_DOMAIN);
    }

    /**
     * Mark ONE of the owner's own notifications read in their domain. Owner-AND-domain
     * scoped, so an id that is not the caller's own owner+domain row is a 404 (no
     * cross-user mark). A re-mark of an already-read OWN row is an idempotent success
     * (200), not a 404 — we only 404 when the id genuinely isn't the caller's. {@code
     * domain} null = SUPERADMIN cross-domain bypass.
     */
    public Mono<Void> markRead(String id, String owner, String domain) {
        requireOwner(owner);
        if (id == null || id.isBlank()) {
            return Mono.error(ApiException.notFound("notification not found"));
        }
        return repo.markRead(id, owner, domain)
                .flatMap(updated -> {
                    if (updated > 0) {
                        return Mono.empty();                 // marked this run
                    }
                    // 0 rows: either the row is already read (own row → idempotent OK)
                    // or the id is not the caller's own owner+domain row (→ 404).
                    return repo.existsForOwner(id, owner, domain)
                            .flatMap(exists -> exists
                                    ? Mono.empty()
                                    : Mono.error(ApiException.notFound("notification not found")));
                })
                .then();
    }

    private static void requireOwner(String owner) {
        if (owner == null || owner.isBlank()) {
            throw ApiException.unauthorized("missing authenticated subject");
        }
    }
}
