package systems.snapdragon.userbff.prefstore;

import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Mono;
import systems.snapdragon.userbff.security.DomainRegistry;
import systems.snapdragon.userbff.security.DomainScope;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Reactive (R2DBC) store for {@code user_preferences_store} — the DURABLE per-user UI
 * preferences the {@code /bff/user/preferences} endpoint reads/upserts. Owner-keyed by
 * {@code user_id} (the Casdoor JWT subject) AND domain-scoped by {@code domain} (the
 * validated-issuer brand), with domain in the COMPOSITE PRIMARY KEY
 * {@code (user_id, pref_key, domain)} — so a multi-brand owner keeps a SEPARATE,
 * owner-isolated value per brand and the upsert is a real PK upsert.
 *
 * <p>Every read/mutate takes the owner id so the SQL is always owner-scoped, PLUS an
 * optional {@code domain} predicate ({@link DomainScope}) so a caller can only ever
 * read/write their OWN preferences in their OWN brand ({@code null} domain =
 * SUPERADMIN cross-domain bypass). The owner id is the caller's JWT subject (set by
 * the service) — never a request field. Mirrors
 * {@link systems.snapdragon.userbff.media.MediaPoisonDecisionRepository} /
 * {@link systems.snapdragon.userbff.preference.UserPreferenceRepository}.
 */
@Repository
public class UserPreferencesStoreRepository {

    private final DatabaseClient db;

    public UserPreferencesStoreRepository(DatabaseClient db) {
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
        var spec = db.sql("SELECT pref_key, pref_value FROM user_preferences_store "
                        + "WHERE user_id = :uid" + DomainScope.andPredicate(domain)
                        + " ORDER BY pref_key")
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

    /** A single durable preference value for the owner in their domain (empty Mono
     *  if unset). */
    public Mono<String> find(String userId, String key, String domain) {
        var spec = db.sql("SELECT pref_value FROM user_preferences_store "
                        + "WHERE user_id = :uid AND pref_key = :k" + DomainScope.andPredicate(domain))
                .bind("uid", userId).bind("k", key);
        return DomainScope.bind(spec, domain).map((row, m) -> row.get("pref_value", String.class)).first();
    }

    /**
     * Upsert one durable preference for the owner in their domain. Portable
     * (Postgres + H2): UPDATE first (owner AND key AND domain scoped), INSERT only if
     * absent (the domain is stamped server-side, never weaker than 'default'). The
     * owner id is the caller's JWT subject (set by the service), so this never touches
     * another user's (or brand's) preference. For the SUPERADMIN bypass ({@code domain}
     * null) the UPDATE matches on owner+key across every brand and an INSERT (when
     * absent) stamps {@code default}.
     */
    public Mono<Void> upsert(String userId, String key, String value, String domain) {
        String dom = DomainScope.isUnscoped(domain) ? DomainRegistry.DEFAULT_DOMAIN : domain;
        var updateSpec = db.sql("UPDATE user_preferences_store SET pref_value = :v, updated_at = now() "
                        + "WHERE user_id = :uid AND pref_key = :k" + DomainScope.andPredicate(domain))
                .bind("uid", userId).bind("k", key).bind("v", value);
        return DomainScope.bind(updateSpec, domain)
                .fetch().rowsUpdated()
                .flatMap(updated -> updated > 0 ? Mono.empty() :
                        db.sql("INSERT INTO user_preferences_store "
                                        + "(user_id, pref_key, pref_value, domain, updated_at) "
                                        + "VALUES (:uid, :k, :v, :dom, now())")
                                .bind("uid", userId).bind("k", key).bind("v", value).bind("dom", dom)
                                .fetch().rowsUpdated().then());
    }

    /** Delete one durable preference for the owner in their domain (idempotent). */
    public Mono<Void> delete(String userId, String key, String domain) {
        var spec = db.sql("DELETE FROM user_preferences_store "
                        + "WHERE user_id = :uid AND pref_key = :k" + DomainScope.andPredicate(domain))
                .bind("uid", userId).bind("k", key);
        return DomainScope.bind(spec, domain).fetch().rowsUpdated().then();
    }
}
