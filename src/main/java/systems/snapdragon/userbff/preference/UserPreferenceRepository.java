package systems.snapdragon.userbff.preference;

import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Reactive (R2DBC) store for {@code user_preference} — a small owner-keyed
 * key/value store (composite PK {@code (user_id, pref_key)}). The home/getting-
 * started guide dismissal lives here as one row per guide key
 * ({@code home-guide-dismissed:<guide>}).
 *
 * <p>Every method takes the owner id so the SQL is always owner-scoped — a caller
 * can only ever read/write their OWN preferences. Mirrors the admin-bff
 * {@code DatabaseClient} pattern.
 */
@Repository
public class UserPreferenceRepository {

    private final DatabaseClient db;

    public UserPreferenceRepository(DatabaseClient db) {
        this.db = db;
    }

    /** All of the owner's preferences as a key→value map. */
    public Mono<Map<String, String>> findAll(String userId) {
        return db.sql("SELECT pref_key, pref_value FROM user_preference WHERE user_id = :uid ORDER BY pref_key")
                .bind("uid", userId)
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

    /** A single preference value for the owner (empty if unset). */
    public Mono<String> find(String userId, String key) {
        return db.sql("SELECT pref_value FROM user_preference WHERE user_id = :uid AND pref_key = :k")
                .bind("uid", userId).bind("k", key)
                .map((row, m) -> row.get("pref_value", String.class)).first();
    }

    /** Find keys with a given value (e.g. the dismissed-guide keys, value 'true'). */
    public Flux<String> findKeysWithValue(String userId, String value) {
        return db.sql("SELECT pref_key FROM user_preference WHERE user_id = :uid AND pref_value = :v ORDER BY pref_key")
                .bind("uid", userId).bind("v", value)
                .map((row, m) -> row.get("pref_key", String.class)).all();
    }

    /**
     * Upsert one preference for the owner. Portable (Postgres + H2): UPDATE first,
     * INSERT only if absent. The owner id is the caller's JWT subject (set by the
     * service), so this never touches another user's preference.
     */
    public Mono<Void> set(String userId, String key, String value) {
        return db.sql("UPDATE user_preference SET pref_value = :v, updated_at = now() "
                        + "WHERE user_id = :uid AND pref_key = :k")
                .bind("uid", userId).bind("k", key).bind("v", value)
                .fetch().rowsUpdated()
                .flatMap(updated -> updated > 0 ? Mono.empty() :
                        db.sql("INSERT INTO user_preference (user_id, pref_key, pref_value, updated_at) "
                                        + "VALUES (:uid, :k, :v, now())")
                                .bind("uid", userId).bind("k", key).bind("v", value)
                                .fetch().rowsUpdated().then());
    }

    public Mono<Void> delete(String userId, String key) {
        return db.sql("DELETE FROM user_preference WHERE user_id = :uid AND pref_key = :k")
                .bind("uid", userId).bind("k", key).fetch().rowsUpdated().then();
    }
}
