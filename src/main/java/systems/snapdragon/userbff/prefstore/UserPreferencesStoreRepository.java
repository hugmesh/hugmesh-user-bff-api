package systems.snapdragon.userbff.prefstore;

import org.springframework.stereotype.Repository;
import reactor.core.publisher.Mono;
import systems.snapdragon.userbff.security.DomainRegistry;
import systems.snapdragon.userbff.security.DomainScope;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Owner-AND-domain-scoped facade over {@link UserPreferencesStoreR2dbcRepository} for
 * {@code user_preferences_store} — the DURABLE per-user UI preferences the
 * {@code /bff/user/preferences} endpoint reads/upserts (composite PK
 * {@code (user_id, pref_key, domain)}). Keeps the original method surface so the
 * service and slice tests are unchanged; all data access now flows through the
 * reactive repository interface (no raw {@code DatabaseClient SQL}).
 *
 * <p>The nullable {@code domain} selects the SCOPED finder ({@code AND domain =
 * :domain}) or the UNSCOPED finder (SUPERADMIN cross-domain bypass).
 */
@Repository
public class UserPreferencesStoreRepository {

    private final UserPreferencesStoreR2dbcRepository repo;

    public UserPreferencesStoreRepository(UserPreferencesStoreR2dbcRepository repo) {
        this.repo = repo;
    }

    /** Back-compat overload — scopes to the platform {@code default} domain. */
    public Mono<Map<String, String>> findAll(String userId) {
        return findAll(userId, DomainRegistry.DEFAULT_DOMAIN);
    }

    /** Back-compat overload — scopes to the platform {@code default} domain. */
    public Mono<String> find(String userId, String key) {
        return find(userId, key, DomainRegistry.DEFAULT_DOMAIN);
    }

    /** Back-compat overload — operates on the platform {@code default} domain. */
    public Mono<Void> upsert(String userId, String key, String value) {
        return upsert(userId, key, value, DomainRegistry.DEFAULT_DOMAIN);
    }

    /** Back-compat overload — scopes to the platform {@code default} domain. */
    public Mono<Void> delete(String userId, String key) {
        return delete(userId, key, DomainRegistry.DEFAULT_DOMAIN);
    }

    /** All of the owner's durable preferences in their domain as an ordered
     *  key→value map ({@code domain} null = SUPERADMIN cross-domain bypass). */
    public Mono<Map<String, String>> findAll(String userId, String domain) {
        var rows = DomainScope.isUnscoped(domain)
                ? repo.findByUserIdOrderByPrefKeyAsc(userId)
                : repo.findByUserIdAndDomainOrderByPrefKeyAsc(userId, domain);
        return rows.collectList().map(list -> {
            Map<String, String> out = new LinkedHashMap<>();
            for (UserPreferencesStoreEntity e : list) out.put(e.prefKey(), e.prefValue());
            return out;
        });
    }

    /** A single durable preference value for the owner in their domain (empty Mono
     *  if unset). */
    public Mono<String> find(String userId, String key, String domain) {
        var found = DomainScope.isUnscoped(domain)
                ? repo.findByUserIdAndPrefKey(userId, key)
                : repo.findByUserIdAndPrefKeyAndDomain(userId, key, domain);
        return found.map(UserPreferencesStoreEntity::prefValue);
    }

    /**
     * Upsert one durable preference for the owner in their domain. Portable
     * (Postgres + H2): UPDATE first (owner AND key AND domain scoped), INSERT only if
     * absent (the domain is stamped server-side). The owner id is the caller's JWT
     * subject (set by the service), so this never touches another user's (or brand's)
     * preference.
     */
    public Mono<Void> upsert(String userId, String key, String value, String domain) {
        String dom = DomainScope.isUnscoped(domain) ? DomainRegistry.DEFAULT_DOMAIN : domain;
        Mono<Long> update = DomainScope.isUnscoped(domain)
                ? repo.updateUnscoped(userId, key, value)
                : repo.updateScoped(userId, key, value, domain);
        return update.flatMap(updated -> updated > 0 ? Mono.empty()
                : repo.insertRow(userId, key, value, dom).then());
    }

    /** Delete one durable preference for the owner in their domain (idempotent). */
    public Mono<Void> delete(String userId, String key, String domain) {
        var deleted = DomainScope.isUnscoped(domain)
                ? repo.deleteByUserIdAndPrefKey(userId, key)
                : repo.deleteByUserIdAndPrefKeyAndDomain(userId, key, domain);
        return deleted.then();
    }
}
