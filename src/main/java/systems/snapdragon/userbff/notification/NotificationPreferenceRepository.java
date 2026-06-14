package systems.snapdragon.userbff.notification;

import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Mono;
import systems.snapdragon.userbff.security.DomainRegistry;
import systems.snapdragon.userbff.security.DomainScope;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Reactive (R2DBC) store for {@code notification_preference} — the per-category
 * notification opt-in/out, MIRRORING {@link systems.snapdragon.userbff.prefstore.UserPreferencesStoreRepository}
 * EXACTLY: owner-keyed by {@code user_subject} (the Casdoor JWT subject) AND
 * domain-scoped by {@code domain} (the validated-issuer brand), with domain in the
 * COMPOSITE PRIMARY KEY {@code (domain, user_subject, category)} — so a multi-brand
 * owner keeps a SEPARATE, owner-isolated preference per brand and the upsert is a real
 * PK upsert (no find-then-insert race window).
 *
 * <p>Every read/mutate takes the owner id so the SQL is always owner-scoped, PLUS an
 * optional {@code domain} predicate ({@link DomainScope}) so a caller can only ever
 * read/write their OWN preferences in their OWN brand ({@code null} domain =
 * SUPERADMIN cross-domain bypass). The owner id is the caller's JWT subject (set by
 * the service) — never a request field.
 */
@Repository
public class NotificationPreferenceRepository {

    private final DatabaseClient db;

    public NotificationPreferenceRepository(DatabaseClient db) {
        this.db = db;
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
     * The owner's RESOLVED enabled state for ONE category in their domain, applied for
     * the internal deliver suppression check: the EXPLICITLY-stored value when a row
     * exists, else the DEFAULT (every category is opt-OUT, so the default is
     * {@code true} / enabled). Owner-AND-category-AND-domain scoped — it reads only the
     * exact target's own row in the target brand, never another user's/brand's.
     *
     * <p>Returns the resolved boolean directly (defaulting to enabled) so the caller
     * never has to distinguish "no row" from "row=true". The FORCED-ON
     * {@code account-restriction} coercion is the SERVICE's concern (the deliver service
     * overrides this for that category) — this method reports the raw stored/default
     * state honestly.
     *
     * @param domain the TARGET brand (a concrete domain from the deliver body, never the
     *               SUPERADMIN null bypass — the system delivers to a specific tenant).
     */
    public Mono<Boolean> isEnabled(String userSubject, String category, String domain) {
        var spec = db.sql("SELECT enabled FROM notification_preference "
                        + "WHERE user_subject = :uid AND category = :cat" + DomainScope.andPredicate(domain))
                .bind("uid", userSubject).bind("cat", category);
        return DomainScope.bind(spec, domain)
                .map((row, m) -> Boolean.TRUE.equals(row.get("enabled", Boolean.class)))
                .first()
                .defaultIfEmpty(Boolean.TRUE);   // no stored row → default ENABLED (opt-out)
    }

    /** All of the owner's category preferences in their domain as an ordered
     *  category→enabled map ({@code domain} null = SUPERADMIN cross-domain bypass).
     *  Only EXPLICITLY-stored rows are returned — the service merges defaults for any
     *  unset category. */
    public Mono<Map<String, Boolean>> findAll(String userSubject, String domain) {
        var spec = db.sql("SELECT category, enabled FROM notification_preference "
                        + "WHERE user_subject = :uid" + DomainScope.andPredicate(domain)
                        + " ORDER BY category")
                .bind("uid", userSubject);
        return DomainScope.bind(spec, domain)
                .map((row, m) -> new Object[] {
                        row.get("category", String.class),
                        row.get("enabled", Boolean.class) })
                .all()
                .collectList()
                .map(rows -> {
                    Map<String, Boolean> out = new LinkedHashMap<>();
                    for (Object[] r : rows) {
                        out.put((String) r[0], Boolean.TRUE.equals(r[1]));
                    }
                    return out;
                });
    }

    /**
     * Upsert one category preference for the owner in their domain. Portable
     * (Postgres + H2): UPDATE first (owner AND category AND domain scoped), INSERT only
     * if absent (the domain is stamped server-side, never weaker than 'default'). The
     * owner id is the caller's JWT subject (set by the service), so this never touches
     * another user's (or brand's) preference. For the SUPERADMIN bypass ({@code domain}
     * null) the UPDATE matches on owner+category across every brand and an INSERT (when
     * absent) stamps {@code default}.
     */
    public Mono<Void> upsert(String userSubject, String category, boolean enabled, String domain) {
        String dom = DomainScope.isUnscoped(domain) ? DomainRegistry.DEFAULT_DOMAIN : domain;
        var updateSpec = db.sql("UPDATE notification_preference SET enabled = :en, updated_at = now() "
                        + "WHERE user_subject = :uid AND category = :cat" + DomainScope.andPredicate(domain))
                .bind("uid", userSubject).bind("cat", category).bind("en", enabled);
        return DomainScope.bind(updateSpec, domain)
                .fetch().rowsUpdated()
                .flatMap(updated -> updated > 0 ? Mono.empty() :
                        db.sql("INSERT INTO notification_preference "
                                        + "(domain, user_subject, category, enabled, updated_at) "
                                        + "VALUES (:dom, :uid, :cat, :en, now())")
                                .bind("dom", dom).bind("uid", userSubject)
                                .bind("cat", category).bind("en", enabled)
                                .fetch().rowsUpdated().then());
    }
}
