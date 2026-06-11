package systems.snapdragon.userbff.media;

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
import java.util.UUID;

/**
 * Reactive (R2DBC) store for {@code media_poison_decision} — the server-owned
 * AI-cloak decision/outcome, owner-keyed by {@code user_id} (Casdoor JWT subject).
 * Every read/mutate takes the owner id so the SQL is always owner-scoped: a caller
 * can only ever record/read their OWN decisions. The id is app-generated (UUID) so
 * the INSERT is portable (Postgres + H2) and returns the new row.
 *
 * <p>Mirrors {@link systems.snapdragon.userbff.block.UserBlockRepository}.
 */
@Repository
public class MediaPoisonDecisionRepository {

    private final DatabaseClient db;

    public MediaPoisonDecisionRepository(DatabaseClient db) {
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

    private static MediaPoisonDecision map(Row row, RowMetadata meta) {
        return new MediaPoisonDecision(
                row.get("id", String.class),
                row.get("user_id", String.class),
                row.get("platform", String.class),
                row.get("media_ref", String.class),
                row.get("mode", String.class),
                row.get("status", String.class),
                row.get("backend", String.class),
                toInstant(row.get("created_at")));
    }

    private static final String COLS =
            "id, user_id, platform, media_ref, mode, status, backend, created_at";

    /**
     * Record a decision for the owner (app-generated id) and return it. The
     * {@code mediaRef} is nullable (a pre-upload failure has no homeserver ref yet);
     * {@code backend} is nullable (no worker ran). The owner is the JWT subject the
     * service passes — never a request field.
     */
    public Mono<MediaPoisonDecision> record(String userId, String platform, String mediaRef,
                                            String mode, String status, String backend) {
        String id = UUID.randomUUID().toString();
        var spec = db.sql("INSERT INTO media_poison_decision "
                        + "(id, user_id, platform, media_ref, mode, status, backend, created_at) "
                        + "VALUES (:id, :uid, :plat, :ref, :mode, :status, :backend, now())")
                .bind("id", id)
                .bind("uid", userId)
                .bind("plat", platform)
                .bind("mode", mode)
                .bind("status", status);
        // media_ref + backend are nullable — bindNull keeps the named-parameter SQL
        // portable (Postgres + H2) when there is no homeserver ref / no worker backend.
        spec = (mediaRef == null) ? spec.bindNull("ref", String.class) : spec.bind("ref", mediaRef);
        spec = (backend == null) ? spec.bindNull("backend", String.class) : spec.bind("backend", backend);
        return spec.fetch().rowsUpdated()
                .then(db.sql("SELECT " + COLS + " FROM media_poison_decision WHERE id = :id")
                        .bind("id", id).map(MediaPoisonDecisionRepository::map).first());
    }

    /** All of the owner's decisions (own data only), newest first. */
    public Flux<MediaPoisonDecision> listForOwner(String userId) {
        return db.sql("SELECT " + COLS + " FROM media_poison_decision "
                        + "WHERE user_id = :uid ORDER BY created_at DESC, id")
                .bind("uid", userId)
                .map(MediaPoisonDecisionRepository::map).all();
    }

    /**
     * The owner's most-recent decision for a {@code media_ref} (the badge poll +
     * already-cloaked repost guard). Owner-AND-ref scoped so a caller can never read
     * another user's decision even with a known ref.
     */
    public Mono<MediaPoisonDecision> findByOwnerAndRef(String userId, String mediaRef) {
        return db.sql("SELECT " + COLS + " FROM media_poison_decision "
                        + "WHERE user_id = :uid AND media_ref = :ref "
                        + "ORDER BY created_at DESC, id LIMIT 1")
                .bind("uid", userId).bind("ref", mediaRef)
                .map(MediaPoisonDecisionRepository::map).first();
    }
}
