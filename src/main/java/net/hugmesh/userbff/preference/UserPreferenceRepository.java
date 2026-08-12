package net.hugmesh.userbff.preference;

import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.commons.tenancy.DomainScope;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Owner-AND-domain-scoped facade over {@link UserPreferenceR2dbcRepository} for
 * {@code user_preference} — a small owner-keyed key/value store (composite PK
 * {@code (user_id, pref_key)}) plus the 010 {@code domain} column. Keeps the original
 * method surface so the home-guide service and slice tests are unchanged; all data
 * access now flows through the reactive repository interface (no raw
 * {@code DatabaseClient SQL}).
 *
 * <p>The nullable {@code domain} selects the SCOPED finder ({@code AND domain =
 * :domain}) or the UNSCOPED finder (SUPERADMIN cross-domain bypass).
 */
@Repository
public class UserPreferenceRepository {

    private final UserPreferenceR2dbcRepository repo;

    public UserPreferenceRepository(UserPreferenceR2dbcRepository repo) {
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

    /** Back-compat overload — scopes to the platform {@code default} domain. */
    public Flux<String> findKeysWithValue(String userId, String value) {
        return findKeysWithValue(userId, value, DomainRegistry.DEFAULT_DOMAIN);
    }

    /** Back-compat overload — operates on the platform {@code default} domain. */
    public Mono<Void> set(String userId, String key, String value) {
        return set(userId, key, value, DomainRegistry.DEFAULT_DOMAIN);
    }

    /** Back-compat overload — scopes to the platform {@code default} domain. */
    public Mono<Void> delete(String userId, String key) {
        return delete(userId, key, DomainRegistry.DEFAULT_DOMAIN);
    }

    /** All of the owner's preferences in their domain as a key→value map. */
    public Mono<Map<String, String>> findAll(String userId, String domain) {
        var rows = DomainScope.isUnscoped(domain)
                ? repo.findByUserIdOrderByPrefKeyAsc(userId)
                : repo.findByUserIdAndDomainOrderByPrefKeyAsc(userId, domain);
        return rows.collectList().map(list -> {
            Map<String, String> out = new LinkedHashMap<>();
            for (UserPreferenceEntity e : list) out.put(e.prefKey(), e.prefValue());
            return out;
        });
    }

    /** A single preference value for the owner in their domain (empty if unset). */
    public Mono<String> find(String userId, String key, String domain) {
        var found = DomainScope.isUnscoped(domain)
                ? repo.findByUserIdAndPrefKey(userId, key)
                : repo.findByUserIdAndPrefKeyAndDomain(userId, key, domain);
        return found.map(UserPreferenceEntity::prefValue);
    }

    /** Find keys with a given value (e.g. the dismissed-guide keys, value 'true') in
     *  the owner's domain. */
    public Flux<String> findKeysWithValue(String userId, String value, String domain) {
        var rows = DomainScope.isUnscoped(domain)
                ? repo.findByUserIdAndPrefValueOrderByPrefKeyAsc(userId, value)
                : repo.findByUserIdAndPrefValueAndDomainOrderByPrefKeyAsc(userId, value, domain);
        return rows.map(UserPreferenceEntity::prefKey);
    }

    /**
     * Upsert one preference for the owner in their domain. Portable (Postgres + H2):
     * UPDATE first (owner AND domain scoped), INSERT only if absent (the domain is
     * stamped server-side). The owner id is the caller's JWT subject (set by the
     * service), so this never touches another user's (or brand's) preference.
     */
    public Mono<Void> set(String userId, String key, String value, String domain) {
        String dom = DomainScope.isUnscoped(domain) ? DomainRegistry.DEFAULT_DOMAIN : domain;
        Mono<Long> update = DomainScope.isUnscoped(domain)
                ? repo.updateUnscoped(userId, key, value)
                : repo.updateScoped(userId, key, value, domain);
        return update.flatMap(updated -> updated > 0 ? Mono.empty()
                : repo.insertRow(userId, key, value, dom).then());
    }

    public Mono<Void> delete(String userId, String key, String domain) {
        var deleted = DomainScope.isUnscoped(domain)
                ? repo.deleteByUserIdAndPrefKey(userId, key)
                : repo.deleteByUserIdAndPrefKeyAndDomain(userId, key, domain);
        return deleted.then();
    }
}
