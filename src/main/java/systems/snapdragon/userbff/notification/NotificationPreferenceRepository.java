package systems.snapdragon.userbff.notification;

import org.springframework.stereotype.Repository;
import reactor.core.publisher.Mono;
import systems.snapdragon.userbff.security.DomainRegistry;
import systems.snapdragon.userbff.security.DomainScope;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Owner-AND-domain-scoped facade over {@link NotificationPreferenceR2dbcRepository} for
 * {@code notification_preference} — the per-category notification opt-in/out (composite
 * PK {@code (domain, user_subject, category)}). Keeps the original method surface
 * ({@code isEnabled} / {@code findAll} / {@code upsert}, with the {@code default}-domain
 * back-compat overloads) so the deliver/preferences services and slice tests are
 * unchanged; all data access now flows through the reactive repository interface (no
 * raw {@code DatabaseClient SQL}).
 */
@Repository
public class NotificationPreferenceRepository {

    private final NotificationPreferenceR2dbcRepository repo;

    public NotificationPreferenceRepository(NotificationPreferenceR2dbcRepository repo) {
        this.repo = repo;
    }

    /** Back-compat overload — scopes to the platform {@code default} domain. */
    public Mono<Map<String, Boolean>> findAll(String userSubject) {
        return findAll(userSubject, DomainRegistry.DEFAULT_DOMAIN);
    }

    /** Back-compat overload — operates on the platform {@code default} domain. */
    public Mono<Void> upsert(String userSubject, String category, boolean enabled) {
        return upsert(userSubject, category, enabled, DomainRegistry.DEFAULT_DOMAIN);
    }

    /**
     * The owner's RESOLVED enabled state for ONE category in their domain: the
     * EXPLICITLY-stored value when a row exists, else the DEFAULT (opt-OUT, so enabled).
     * Owner-AND-category-AND-domain scoped.
     *
     * @param domain the TARGET brand (a concrete domain from the deliver body, never the
     *               SUPERADMIN null bypass — the system delivers to a specific tenant).
     */
    public Mono<Boolean> isEnabled(String userSubject, String category, String domain) {
        var found = DomainScope.isUnscoped(domain)
                ? repo.findByUserSubjectAndCategory(userSubject, category)
                : repo.findByUserSubjectAndCategoryAndDomain(userSubject, category, domain);
        return found.map(NotificationPreferenceEntity::enabled)
                .defaultIfEmpty(Boolean.TRUE);   // no stored row → default ENABLED (opt-out)
    }

    /** All of the owner's category preferences in their domain as an ordered
     *  category→enabled map ({@code domain} null = SUPERADMIN cross-domain bypass).
     *  Only EXPLICITLY-stored rows are returned — the service merges defaults. */
    public Mono<Map<String, Boolean>> findAll(String userSubject, String domain) {
        var rows = DomainScope.isUnscoped(domain)
                ? repo.findByUserSubjectOrderByCategoryAsc(userSubject)
                : repo.findByUserSubjectAndDomainOrderByCategoryAsc(userSubject, domain);
        return rows.collectList().map(list -> {
            Map<String, Boolean> out = new LinkedHashMap<>();
            for (NotificationPreferenceEntity e : list) out.put(e.category(), e.enabled());
            return out;
        });
    }

    /**
     * Upsert one category preference for the owner in their domain. Portable
     * (Postgres + H2): UPDATE first (owner AND category AND domain scoped), INSERT only
     * if absent (the domain is stamped server-side). For the SUPERADMIN bypass
     * ({@code domain} null) the UPDATE matches on owner+category across every brand and
     * an INSERT (when absent) stamps {@code default}.
     */
    public Mono<Void> upsert(String userSubject, String category, boolean enabled, String domain) {
        String dom = DomainScope.isUnscoped(domain) ? DomainRegistry.DEFAULT_DOMAIN : domain;
        Mono<Long> update = DomainScope.isUnscoped(domain)
                ? repo.updateUnscoped(userSubject, category, enabled)
                : repo.updateScoped(userSubject, category, enabled, domain);
        return update.flatMap(updated -> updated > 0 ? Mono.empty()
                : repo.insertRow(dom, userSubject, category, enabled).then());
    }
}
