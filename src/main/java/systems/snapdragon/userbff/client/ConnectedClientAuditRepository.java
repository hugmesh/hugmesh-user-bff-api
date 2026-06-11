package systems.snapdragon.userbff.client;

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
 * Reactive (R2DBC) store for {@code connected_client_audit} — owner-keyed by
 * {@code owner} (Casdoor JWT subject). Every method takes the owner id so the SQL is
 * always owner-scoped; the id is app-generated (UUID) so the INSERT is portable
 * (Postgres + H2) and returns the new row. {@code revoke} is owner-AND-id scoped so a
 * caller can never revoke another user's client even with a guessed id.
 */
@Repository
public class ConnectedClientAuditRepository {

    private final DatabaseClient db;

    public ConnectedClientAuditRepository(DatabaseClient db) {
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

    private static ConnectedClient map(Row row, RowMetadata meta) {
        return new ConnectedClient(
                row.get("id", String.class),
                row.get("owner", String.class),
                row.get("platform", String.class),
                row.get("client_kind", String.class),
                row.get("external_ref", String.class),
                row.get("label", String.class),
                toInstant(row.get("created_at")),
                toInstant(row.get("revoked_at")));
    }

    /** All of the owner's audited clients (own data only), newest first. */
    public Flux<ConnectedClient> listForOwner(String owner) {
        return db.sql("SELECT id, owner, platform, client_kind, external_ref, label, "
                        + "created_at, revoked_at FROM connected_client_audit "
                        + "WHERE owner = :owner ORDER BY created_at DESC, id")
                .bind("owner", owner)
                .map(ConnectedClientAuditRepository::map).all();
    }

    /** The owner's audited client by id (own data only), or empty. */
    public Mono<ConnectedClient> find(String owner, String id) {
        return db.sql("SELECT id, owner, platform, client_kind, external_ref, label, "
                        + "created_at, revoked_at FROM connected_client_audit "
                        + "WHERE owner = :owner AND id = :id")
                .bind("owner", owner).bind("id", id)
                .map(ConnectedClientAuditRepository::map).first();
    }

    /**
     * Record an audit row for one of the owner's clients (app-generated id) and return
     * it. Used both when the homeserver list-seam surfaces a client we have no row for
     * yet (record-on-observe) and as the audit anchor a revoke later stamps.
     */
    public Mono<ConnectedClient> record(String owner, String platform, String clientKind,
                                        String externalRef, String label) {
        String id = UUID.randomUUID().toString();
        return db.sql("INSERT INTO connected_client_audit "
                        + "(id, owner, platform, client_kind, external_ref, label, created_at) "
                        + "VALUES (:id, :owner, :platform, :kind, :ref, :label, now())")
                .bind("id", id).bind("owner", owner).bind("platform", platform)
                .bind("kind", clientKind).bind("ref", externalRef)
                .bind("label", label == null ? "" : label)
                .fetch().rowsUpdated()
                .then(find(owner, id));
    }

    /**
     * Stamp {@code revoked_at} on the owner's client (scoped by BOTH owner and id, and
     * only when not already revoked) so a double-revoke is idempotent. Returns the
     * number of rows stamped (0 = nothing active for this owner+id).
     */
    public Mono<Long> revoke(String owner, String id) {
        return db.sql("UPDATE connected_client_audit SET revoked_at = now() "
                        + "WHERE owner = :owner AND id = :id AND revoked_at IS NULL")
                .bind("owner", owner).bind("id", id).fetch().rowsUpdated();
    }
}
