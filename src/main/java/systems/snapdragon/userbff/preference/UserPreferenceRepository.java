package systems.snapdragon.userbff.preference;

import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.snapdragon.userbff.security.DomainRegistry;
import systems.snapdragon.userbff.security.DomainScope;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Reactive (R2DBC) store for {@code user_preference} — a small owner-keyed
 * key/value store (composite PK {@code (user_id, pref_key)}) AND domain-scoped by
 * {@code domain} (the validated-issuer brand). The home/getting-started guide
 * dismissal lives here as one row per guide key
 * ({@code home-guide-dismissed:<guide>}).
 *
 * <p>Every method takes the owner id so the SQL is always owner-scoped, PLUS an
 * optional {@code domain} predicate ({@link DomainScope}) so a caller can only ever
 * read/write their OWN preferences in their OWN brand ({@code null} domain =
 * SUPERADMIN cross-domain bypass). Mirrors the admin-bff {@code DatabaseClient}
 * pattern.
 */
@Repository
public class UserPreferenceRepository {

    private final DatabaseClient db;

    public UserPreferenceRepository(DatabaseClient db) {
        this.db = db;
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
        var spec = db.sql("SELECT pref_key, pref_value FROM user_preference WHERE user_id = :uid"
                        + DomainScope.andPredicate(domain) + " ORDER BY pref_key")
                .bind("uid", userId);
        return DomainScope.bind(spec, domain)
                .map((row, m) -> new String[] {
                        row.get("pref_key", String.class), row.get("pref_value", String.class) })
                .all()
                .collectList()
                .map(rows -> {
                    Map<String, String> out = new LinkedHashMap<>();
                    for (String[] r : rows) out.put(r[0], r[1]);
                    return out;
                });
    }

    /** A single preference value for the owner in their domain (empty if unset). */
    public Mono<String> find(String userId, String key, String domain) {
        var spec = db.sql("SELECT pref_value FROM user_preference WHERE user_id = :uid AND pref_key = :k"
                        + DomainScope.andPredicate(domain))
                .bind("uid", userId).bind("k", key);
        return DomainScope.bind(spec, domain).map((row, m) -> row.get("pref_value", String.class)).first();
    }

    /** Find keys with a given value (e.g. the dismissed-guide keys, value 'true') in
     *  the owner's domain. */
    public Flux<String> findKeysWithValue(String userId, String value, String domain) {
        var spec = db.sql("SELECT pref_key FROM user_preference WHERE user_id = :uid AND pref_value = :v"
                        + DomainScope.andPredicate(domain) + " ORDER BY pref_key")
                .bind("uid", userId).bind("v", value);
        return DomainScope.bind(spec, domain).map((row, m) -> row.get("pref_key", String.class)).all();
    }

    /**
     * Upsert one preference for the owner in their domain. Portable (Postgres + H2):
     * UPDATE first (owner AND domain scoped), INSERT only if absent (the domain is
     * stamped server-side). The owner id is the caller's JWT subject (set by the
     * service), so this never touches another user's (or brand's) preference.
     */
    public Mono<Void> set(String userId, String key, String value, String domain) {
        String dom = DomainScope.isUnscoped(domain) ? DomainRegistry.DEFAULT_DOMAIN : domain;
        var updateSpec = db.sql("UPDATE user_preference SET pref_value = :v, updated_at = now() "
                        + "WHERE user_id = :uid AND pref_key = :k" + DomainScope.andPredicate(domain))
                .bind("uid", userId).bind("k", key).bind("v", value);
        return DomainScope.bind(updateSpec, domain)
                .fetch().rowsUpdated()
                .flatMap(updated -> updated > 0 ? Mono.empty() :
                        db.sql("INSERT INTO user_preference (user_id, pref_key, pref_value, domain, updated_at) "
                                        + "VALUES (:uid, :k, :v, :dom, now())")
                                .bind("uid", userId).bind("k", key).bind("v", value).bind("dom", dom)
                                .fetch().rowsUpdated().then());
    }

    public Mono<Void> delete(String userId, String key, String domain) {
        var spec = db.sql("DELETE FROM user_preference WHERE user_id = :uid AND pref_key = :k"
                        + DomainScope.andPredicate(domain))
                .bind("uid", userId).bind("k", key);
        return DomainScope.bind(spec, domain).fetch().rowsUpdated().then();
    }
}
