package systems.snapdragon.userbff.profile;

import io.r2dbc.spi.Row;
import io.r2dbc.spi.RowMetadata;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Mono;

/**
 * Reactive (R2DBC) store for {@code user_profile} — keyed by the owner
 * ({@code user_id} = Casdoor JWT subject). Every method takes the owner id so the
 * SQL is always owner-scoped; there is deliberately NO "find any profile by id"
 * that the caller controls — the service always passes the JWT subject. Mirrors
 * the admin-bff {@code DatabaseClient.sql(...).bind().map()} pattern.
 */
@Repository
public class UserProfileRepository {

    private final DatabaseClient db;

    public UserProfileRepository(DatabaseClient db) {
        this.db = db;
    }

    private static UserProfile map(Row row, RowMetadata meta) {
        return new UserProfile(
                row.get("user_id", String.class),
                row.get("gender", String.class),
                row.get("pronouns", String.class),
                row.get("timezone", String.class),
                row.get("display_name", String.class),
                row.get("visibility", String.class),
                Boolean.TRUE.equals(row.get("vanity_subdomain_enabled", Boolean.class)),
                row.get("vanity_username", String.class));
    }

    /** The owner's profile, or empty if they have never created one. */
    public Mono<UserProfile> find(String userId) {
        return db.sql("SELECT user_id, gender, pronouns, timezone, display_name, "
                        + "visibility, vanity_subdomain_enabled, vanity_username "
                        + "FROM user_profile WHERE user_id = :uid")
                .bind("uid", userId)
                .map(UserProfileRepository::map).first();
    }

    /**
     * Upsert the owner's profile. Portable (Postgres + H2): UPDATE first, then
     * INSERT only if no row was updated. The owner id is always the caller's JWT
     * subject (set by the service), so this can never touch another user's row.
     */
    public Mono<UserProfile> save(UserProfile p) {
        var spec = db.sql("UPDATE user_profile SET gender = :g, pronouns = :pr, timezone = :tz, "
                        + "display_name = :dn, visibility = :vis, vanity_subdomain_enabled = :vse, "
                        + "vanity_username = :vu, updated_at = now() WHERE user_id = :uid")
                .bind("uid", p.userId())
                .bind("vis", p.visibility())
                .bind("vse", p.vanitySubdomainEnabled())
                .bind("g", nz(p.gender()))
                .bind("pr", nz(p.pronouns()))
                .bind("tz", nz(p.timezone()))
                .bind("dn", nz(p.displayName()));
        spec = bindVanityUsername(spec, p);
        return spec.fetch().rowsUpdated()
                .flatMap(updated -> updated > 0 ? Mono.just(p) : insert(p));
    }

    private Mono<UserProfile> insert(UserProfile p) {
        var spec = db.sql("INSERT INTO user_profile (user_id, gender, pronouns, timezone, display_name, "
                        + "visibility, vanity_subdomain_enabled, vanity_username, updated_at) "
                        + "VALUES (:uid, :g, :pr, :tz, :dn, :vis, :vse, :vu, now())")
                .bind("uid", p.userId())
                .bind("vis", p.visibility())
                .bind("vse", p.vanitySubdomainEnabled())
                .bind("g", nz(p.gender()))
                .bind("pr", nz(p.pronouns()))
                .bind("tz", nz(p.timezone()))
                .bind("dn", nz(p.displayName()));
        spec = bindVanityUsername(spec, p);
        return spec.fetch().rowsUpdated()
                .thenReturn(p);
    }

    /** Bind the nullable {@code vanity_username} — a real NULL (not "") so the
     *  reserved-name CHECK's {@code IS NULL} branch fires when vanity is disabled. */
    private static DatabaseClient.GenericExecuteSpec bindVanityUsername(
            DatabaseClient.GenericExecuteSpec spec, UserProfile p) {
        return p.vanityUsername() == null
                ? spec.bindNull("vu", String.class)
                : spec.bind("vu", p.vanityUsername());
    }

    /** Delete the owner's profile (own data only). */
    public Mono<Void> delete(String userId) {
        return db.sql("DELETE FROM user_profile WHERE user_id = :uid")
                .bind("uid", userId).fetch().rowsUpdated().then();
    }

    /** Bind-safe empty-string for nullable text columns (avoids bindNull churn). */
    private static String nz(String s) {
        return s == null ? "" : s;
    }
}
