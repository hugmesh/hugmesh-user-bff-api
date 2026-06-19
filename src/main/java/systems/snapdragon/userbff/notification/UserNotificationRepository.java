package systems.snapdragon.userbff.notification;

import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.snapdragon.commons.security.DomainRegistry;
import systems.snapdragon.commons.tenancy.DomainScope;

import java.util.UUID;

/**
 * Owner-AND-domain-scoped facade over {@link UserNotificationR2dbcRepository} for
 * {@code user_notifications} — the always-on in-app FLOOR inbox. Keeps the original
 * method surface ({@code listForOwner} / {@code markRead} / {@code insertIfAbsent} /
 * {@code existsById} / {@code existsForOwner} + the package-private {@code insertForTest},
 * with the {@code default}-domain back-compat overloads) so the read/mark-read/deliver
 * services and slice tests are unchanged; all data access now flows through the reactive
 * repository interface (no raw {@code DatabaseClient SQL}).
 *
 * <p>SHIPS DARK in PR1: the only production write path is {@link #insertIfAbsent}
 * (service-principal internal deliver). {@link #insertForTest} exists ONLY for the slice
 * tests to seed rows.
 */
@Repository
public class UserNotificationRepository {

    /** The server-side cap on a single inbox page — the read is always bounded. */
    public static final int MAX_PAGE = 100;

    private final UserNotificationR2dbcRepository repo;

    public UserNotificationRepository(UserNotificationR2dbcRepository repo) {
        this.repo = repo;
    }

    private static UserNotification toWire(UserNotificationEntity e) {
        return new UserNotification(
                e.id(), e.userSubject(), e.category(), e.title(), e.body(),
                e.createdAt(), e.readAt());
    }

    /** Back-compat overload — scopes to the platform {@code default} domain. */
    public Flux<UserNotification> listForOwner(String userSubject, int limit) {
        return listForOwner(userSubject, DomainRegistry.DEFAULT_DOMAIN, limit);
    }

    /**
     * The owner's in-app notifications in their domain (own data only), newest first,
     * capped at {@link #MAX_PAGE} ({@code domain} null = SUPERADMIN cross-domain
     * bypass). A non-positive or over-cap {@code limit} clamps into {@code [1, MAX_PAGE]}.
     */
    public Flux<UserNotification> listForOwner(String userSubject, String domain, int limit) {
        int cap = clamp(limit);
        var rows = DomainScope.isUnscoped(domain)
                ? repo.listUnscoped(userSubject, cap)
                : repo.listScoped(userSubject, domain, cap);
        return rows.map(UserNotificationRepository::toWire);
    }

    /** Back-compat overload — scopes to the platform {@code default} domain. */
    public Mono<Long> markRead(String id, String userSubject) {
        return markRead(id, userSubject, DomainRegistry.DEFAULT_DOMAIN);
    }

    /**
     * Mark ONE notification read for the owner in their domain. Owner-AND-domain-AND-id
     * scoped (and only if currently unread, so a re-mark is a no-op). Returns the number
     * of rows updated — 0 means the id is not the caller's own owner+domain unread row.
     * {@code domain} null = SUPERADMIN cross-domain bypass.
     */
    public Mono<Long> markRead(String id, String userSubject, String domain) {
        return DomainScope.isUnscoped(domain)
                ? repo.markReadUnscoped(id, userSubject)
                : repo.markReadScoped(id, userSubject, domain);
    }

    /**
     * INSERT-IF-ABSENT one delivered in-app notification keyed by the caller-supplied
     * DETERMINISTIC {@code id}. The ONLY production write path. Idempotent by
     * construction (existence pre-check on the PK; a retry presents the same id → no
     * second row). The {@code (domain, userSubject)} target is taken EXPLICITLY (the
     * service principal acts for the SYSTEM for a named target).
     *
     * @return {@code true} iff a NEW row was inserted; {@code false} iff the id already
     *         existed (a deduped retry).
     */
    public Mono<Boolean> insertIfAbsent(String id, String domain, String userSubject,
                                        String category, String title, String body) {
        return repo.existsById(id).flatMap(exists -> exists
                ? Mono.just(false)
                : repo.insertRow(id, domain, userSubject, category, title, body).thenReturn(true));
    }

    /** True iff a row with this PK id exists (any owner/domain) — the idempotency probe
     *  for {@link #insertIfAbsent}. */
    public Mono<Boolean> existsById(String id) {
        return repo.existsById(id);
    }

    /**
     * True iff a row with this id exists for the owner in their domain (regardless of
     * read state). Lets the service distinguish "already-read own row" from "not the
     * caller's row" after a 0-row {@link #markRead}. Owner+domain scoped.
     */
    public Mono<Boolean> existsForOwner(String id, String userSubject, String domain) {
        return DomainScope.isUnscoped(domain)
                ? repo.existsByIdAndUserSubject(id, userSubject)
                : repo.existsByIdAndUserSubjectAndDomain(id, userSubject, domain);
    }

    private static int clamp(int limit) {
        if (limit < 1) return 1;
        return Math.min(limit, MAX_PAGE);
    }

    /**
     * TEST-ONLY seed of one notification row (PR1 ships dark). Package-private so it
     * never leaks into the production read/mark-read API surface; the slice tests use it
     * to prove owner+domain read isolation and the mark-read 404 boundary.
     */
    Mono<String> insertForTest(String userSubject, String category, String title,
                               String body, String domain) {
        String id = UUID.randomUUID().toString();
        String dom = DomainScope.isUnscoped(domain) ? DomainRegistry.DEFAULT_DOMAIN : domain;
        return repo.insertRow(id, dom, userSubject, category, title, body).thenReturn(id);
    }
}
