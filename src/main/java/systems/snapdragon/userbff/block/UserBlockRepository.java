package systems.snapdragon.userbff.block;

import io.r2dbc.spi.Row;
import io.r2dbc.spi.RowMetadata;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.snapdragon.userbff.security.DomainRegistry;
import systems.snapdragon.userbff.security.DomainScope;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.UUID;

/**
 * Reactive (R2DBC) store for {@code user_block} — owner-keyed by {@code user_id}
 * (Casdoor JWT subject) AND domain-scoped by {@code domain} (the validated-issuer
 * brand). Every method takes the owner id so the SQL is always owner-scoped, PLUS an
 * optional {@code domain} predicate ({@link DomainScope}) so a caller only ever
 * touches rows in their OWN brand; a {@code null} domain is the SUPERADMIN
 * cross-domain bypass (no predicate). The id is app-generated (UUID) so the INSERT is
 * portable (Postgres + H2) and returns the new row. {@code delete} is
 * owner-AND-domain-AND-id scoped so a caller can never delete another user's (or
 * another brand's) block even with a guessed id.
 */
@Repository
public class UserBlockRepository {

    private final DatabaseClient db;

    public UserBlockRepository(DatabaseClient db) {
        this.db = db;
    }

    private static UserBlock map(Row row, RowMetadata meta) {
        Object tsRaw = row.get("ts");
        Instant ts = switch (tsRaw) {
            case Instant i -> i;
            case LocalDateTime ldt -> ldt.toInstant(ZoneOffset.UTC);
            case java.time.OffsetDateTime odt -> odt.toInstant();
            case null, default -> null;
        };
        return new UserBlock(
                row.get("id", String.class),
                row.get("user_id", String.class),
                row.get("target", String.class),
                row.get("platform", String.class),
                ts);
    }

    /** Back-compat overload — scopes to the platform {@code default} domain. */
    public Flux<UserBlock> listForOwner(String userId) {
        return listForOwner(userId, DomainRegistry.DEFAULT_DOMAIN);
    }

    /** Back-compat overload — stamps the platform {@code default} domain. */
    public Mono<UserBlock> add(String userId, String target, String platform) {
        return add(userId, target, platform, DomainRegistry.DEFAULT_DOMAIN);
    }

    /** Back-compat overload — scopes to the platform {@code default} domain. */
    public Mono<Long> delete(String userId, String id) {
        return delete(userId, id, DomainRegistry.DEFAULT_DOMAIN);
    }

    /** All of the owner's blocks in their domain (own data only; SUPERADMIN sees all
     *  domains when {@code domain} is null). */
    public Flux<UserBlock> listForOwner(String userId, String domain) {
        var spec = db.sql("SELECT id, user_id, target, platform, ts FROM user_block "
                        + "WHERE user_id = :uid" + DomainScope.andPredicate(domain)
                        + " ORDER BY ts DESC, id")
                .bind("uid", userId);
        return DomainScope.bind(spec, domain).map(UserBlockRepository::map).all();
    }

    /** Insert a block for the owner in their domain (app-generated id) and return it.
     *  The domain is stamped SERVER-SIDE (the caller's validated-issuer brand), never
     *  a request field. SUPERADMIN ({@code domain} null) defaults the row to the
     *  platform default domain so a stamped row always carries a concrete brand. */
    public Mono<UserBlock> add(String userId, String target, String platform, String domain) {
        String id = UUID.randomUUID().toString();
        String dom = DomainScope.isUnscoped(domain) ? DomainRegistry.DEFAULT_DOMAIN : domain;
        return db.sql("INSERT INTO user_block (id, user_id, target, platform, domain, ts) "
                        + "VALUES (:id, :uid, :t, :p, :dom, now())")
                .bind("id", id).bind("uid", userId).bind("t", target).bind("p", platform)
                .bind("dom", dom)
                .fetch().rowsUpdated()
                .then(db.sql("SELECT id, user_id, target, platform, ts FROM user_block WHERE id = :id")
                        .bind("id", id).map(UserBlockRepository::map).first());
    }

    /** Delete one of the owner's blocks (scoped by owner AND domain AND id). */
    public Mono<Long> delete(String userId, String id, String domain) {
        var spec = db.sql("DELETE FROM user_block WHERE user_id = :uid AND id = :id"
                        + DomainScope.andPredicate(domain))
                .bind("uid", userId).bind("id", id);
        return DomainScope.bind(spec, domain).fetch().rowsUpdated();
    }
}
