package systems.snapdragon.userbff.block;

import io.r2dbc.spi.Row;
import io.r2dbc.spi.RowMetadata;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.UUID;

/**
 * Reactive (R2DBC) store for {@code user_block} — owner-keyed by {@code user_id}
 * (Casdoor JWT subject). Every method takes the owner id so the SQL is always
 * owner-scoped; the id is app-generated (UUID) so the INSERT is portable
 * (Postgres + H2) and returns the new row. {@code delete} is owner-AND-id scoped so
 * a caller can never delete another user's block even with a guessed id.
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

    /** All of the owner's blocks (own data only). */
    public Flux<UserBlock> listForOwner(String userId) {
        return db.sql("SELECT id, user_id, target, platform, ts FROM user_block "
                        + "WHERE user_id = :uid ORDER BY ts DESC, id")
                .bind("uid", userId)
                .map(UserBlockRepository::map).all();
    }

    /** Insert a block for the owner (app-generated id) and return it. */
    public Mono<UserBlock> add(String userId, String target, String platform) {
        String id = UUID.randomUUID().toString();
        return db.sql("INSERT INTO user_block (id, user_id, target, platform, ts) "
                        + "VALUES (:id, :uid, :t, :p, now())")
                .bind("id", id).bind("uid", userId).bind("t", target).bind("p", platform)
                .fetch().rowsUpdated()
                .then(db.sql("SELECT id, user_id, target, platform, ts FROM user_block WHERE id = :id")
                        .bind("id", id).map(UserBlockRepository::map).first());
    }

    /** Delete one of the owner's blocks (scoped by BOTH owner and id). */
    public Mono<Long> delete(String userId, String id) {
        return db.sql("DELETE FROM user_block WHERE user_id = :uid AND id = :id")
                .bind("uid", userId).bind("id", id).fetch().rowsUpdated();
    }
}
