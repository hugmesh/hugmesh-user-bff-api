package systems.snapdragon.userbff.silence;

import io.r2dbc.spi.Row;
import io.r2dbc.spi.RowMetadata;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;

/**
 * Reactive (R2DBC) store for {@code self_silence} — owner-keyed by {@code user_id}
 * (Casdoor JWT subject). A user has at most one row (PK on {@code user_id}); every
 * method that mutates is owner-scoped so a caller can only touch their OWN silence.
 *
 * <p>The row is the source of truth and {@code expires_at} is authoritative. The
 * scheduled wake uses {@link #findOverdueActive(Instant)} to re-select expired-but-
 * uncleared rows (including on boot) and {@link #clear(String)} to stamp
 * {@code cleared_at}. {@code DELETE}-free clearing keeps the audit history of a
 * user's self-silences.
 */
@Repository
public class SelfSilenceRepository {

    private final DatabaseClient db;

    public SelfSilenceRepository(DatabaseClient db) {
        this.db = db;
    }

    private static Instant toInstant(Object raw) {
        return switch (raw) {
            case Instant i -> i;
            case LocalDateTime ldt -> ldt.toInstant(ZoneOffset.UTC);
            case OffsetDateTime odt -> odt.toInstant();
            case null, default -> null;
        };
    }

    private static SelfSilence map(Row row, RowMetadata meta) {
        return new SelfSilence(
                row.get("user_id", String.class),
                toInstant(row.get("started_at")),
                toInstant(row.get("expires_at")),
                toInstant(row.get("cleared_at")),
                row.get("reason", String.class),
                toInstant(row.get("updated_at")));
    }

    /** The owner's current silence row (active or cleared), or empty if none ever. */
    public Mono<SelfSilence> find(String userId) {
        return db.sql("SELECT user_id, started_at, expires_at, cleared_at, reason, updated_at "
                        + "FROM self_silence WHERE user_id = :uid")
                .bind("uid", userId)
                .map(SelfSilenceRepository::map).first();
    }

    /**
     * Activate (or re-activate) the owner's silence: upsert a row with the given
     * window/reason and a NULL {@code cleared_at}. Implemented as
     * DELETE-then-INSERT (portable across Postgres + H2; the PK keeps it to one row)
     * so re-activating after a prior cleared silence starts a clean active window.
     * Returns the freshly-written row.
     */
    public Mono<SelfSilence> activate(String userId, Instant expiresAt, String reason) {
        return db.sql("DELETE FROM self_silence WHERE user_id = :uid")
                .bind("uid", userId).fetch().rowsUpdated()
                .then(db.sql("INSERT INTO self_silence "
                                + "(user_id, started_at, expires_at, cleared_at, reason, updated_at) "
                                + "VALUES (:uid, now(), :exp, NULL, :reason, now())")
                        .bind("uid", userId)
                        .bind("exp", LocalDateTime.ofInstant(expiresAt, ZoneOffset.UTC))
                        .bind("reason", reason == null ? "" : reason)
                        .fetch().rowsUpdated())
                .then(find(userId));
    }

    /**
     * Clear (stamp {@code cleared_at}) the owner's ACTIVE silence. Owner-scoped and
     * only-if-active ({@code cleared_at IS NULL}) so a double-cancel / expiry race is
     * idempotent. Returns the number of rows cleared (0 = nothing active).
     */
    public Mono<Long> clear(String userId) {
        return db.sql("UPDATE self_silence SET cleared_at = now(), updated_at = now() "
                        + "WHERE user_id = :uid AND cleared_at IS NULL")
                .bind("uid", userId).fetch().rowsUpdated();
    }

    /**
     * Active silences whose {@code expires_at} is at/before {@code asOf} — the
     * scheduled wake's work list. Re-selected on every tick (and on boot) so a
     * restart never loses a pending wake. Bounded by the partial active index.
     */
    public Flux<SelfSilence> findOverdueActive(Instant asOf) {
        return db.sql("SELECT user_id, started_at, expires_at, cleared_at, reason, updated_at "
                        + "FROM self_silence WHERE cleared_at IS NULL AND expires_at <= :asOf "
                        + "ORDER BY expires_at")
                .bind("asOf", LocalDateTime.ofInstant(asOf, ZoneOffset.UTC))
                .map(SelfSilenceRepository::map).all();
    }
}
