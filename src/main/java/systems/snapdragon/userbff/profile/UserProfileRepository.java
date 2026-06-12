package systems.snapdragon.userbff.profile;

import io.r2dbc.spi.Row;
import io.r2dbc.spi.RowMetadata;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Mono;
import systems.snapdragon.userbff.security.DomainRegistry;
import systems.snapdragon.userbff.security.DomainScope;

/**
 * Reactive (R2DBC) store for {@code user_profile} — keyed by the owner
 * ({@code user_id} = Casdoor JWT subject) AND domain-scoped by {@code domain} (the
 * validated-issuer brand). Every method takes the owner id so the SQL is always
 * owner-scoped, PLUS an optional {@code domain} predicate ({@link DomainScope}) so a
 * caller only ever touches a profile in their OWN brand; a {@code null} domain is
 * the SUPERADMIN cross-domain bypass (no predicate). There is deliberately NO "find
 * any profile by id" that the caller controls — the service always passes the JWT
 * subject. Mirrors the admin-bff {@code DatabaseClient.sql(...).bind().map()}
 * pattern.
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
                row.get("vanity_username", String.class),
                row.get("screen_reader_name", String.class));
    }

    /** Back-compat overload — scopes to the platform {@code default} domain. */
    public Mono<UserProfile> find(String userId) {
        return find(userId, DomainRegistry.DEFAULT_DOMAIN);
    }

    /** Back-compat overload — stamps/operates on the platform {@code default} domain. */
    public Mono<UserProfile> save(UserProfile p) {
        return save(p, DomainRegistry.DEFAULT_DOMAIN);
    }

    /** Back-compat overload — scopes to the platform {@code default} domain. */
    public Mono<Void> delete(String userId) {
        return delete(userId, DomainRegistry.DEFAULT_DOMAIN);
    }

    /** The owner's profile in their domain, or empty if they have never created one
     *  ({@code domain} null = SUPERADMIN cross-domain bypass). */
    public Mono<UserProfile> find(String userId, String domain) {
        var spec = db.sql("SELECT user_id, gender, pronouns, timezone, display_name, "
                        + "visibility, vanity_subdomain_enabled, vanity_username, screen_reader_name "
                        + "FROM user_profile WHERE user_id = :uid" + DomainScope.andPredicate(domain))
                .bind("uid", userId);
        return DomainScope.bind(spec, domain).map(UserProfileRepository::map).first();
    }

    /**
     * Upsert the owner's profile in their domain. Portable (Postgres + H2): UPDATE
     * first (owner AND domain scoped), then INSERT only if no row was updated (the
     * domain is stamped server-side). The owner id is always the caller's JWT subject
     * (set by the service), so this can never touch another user's row; the domain
     * predicate additionally prevents touching another brand's row.
     */
    public Mono<UserProfile> save(UserProfile p, String domain) {
        var spec = db.sql("UPDATE user_profile SET gender = :g, pronouns = :pr, timezone = :tz, "
                        + "display_name = :dn, visibility = :vis, vanity_subdomain_enabled = :vse, "
                        + "vanity_username = :vu, screen_reader_name = :srn, updated_at = now() "
                        + "WHERE user_id = :uid" + DomainScope.andPredicate(domain))
                .bind("uid", p.userId())
                .bind("vis", p.visibility())
                .bind("vse", p.vanitySubdomainEnabled())
                .bind("g", nz(p.gender()))
                .bind("pr", nz(p.pronouns()))
                .bind("tz", nz(p.timezone()))
                .bind("dn", nz(p.displayName()))
                .bind("srn", nz(p.screenReaderName()));
        spec = bindVanityUsername(spec, p);
        spec = DomainScope.bind(spec, domain);
        return spec.fetch().rowsUpdated()
                .flatMap(updated -> updated > 0 ? Mono.just(p) : insert(p, domain));
    }

    private Mono<UserProfile> insert(UserProfile p, String domain) {
        String dom = DomainScope.isUnscoped(domain) ? DomainRegistry.DEFAULT_DOMAIN : domain;
        var spec = db.sql("INSERT INTO user_profile (user_id, gender, pronouns, timezone, display_name, "
                        + "visibility, vanity_subdomain_enabled, vanity_username, screen_reader_name, domain, updated_at) "
                        + "VALUES (:uid, :g, :pr, :tz, :dn, :vis, :vse, :vu, :srn, :dom, now())")
                .bind("uid", p.userId())
                .bind("vis", p.visibility())
                .bind("vse", p.vanitySubdomainEnabled())
                .bind("g", nz(p.gender()))
                .bind("pr", nz(p.pronouns()))
                .bind("tz", nz(p.timezone()))
                .bind("dn", nz(p.displayName()))
                .bind("srn", nz(p.screenReaderName()))
                .bind("dom", dom);
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

    /** Delete the owner's profile (own data only; owner AND domain scoped). */
    public Mono<Void> delete(String userId, String domain) {
        var spec = db.sql("DELETE FROM user_profile WHERE user_id = :uid"
                        + DomainScope.andPredicate(domain))
                .bind("uid", userId);
        return DomainScope.bind(spec, domain).fetch().rowsUpdated().then();
    }

    /** Bind-safe empty-string for nullable text columns (avoids bindNull churn). */
    private static String nz(String s) {
        return s == null ? "" : s;
    }
}
