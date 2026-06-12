package systems.snapdragon.userbff.client;

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
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.UUID;

/**
 * Reactive (R2DBC) store for {@code connected_client_audit} — owner-keyed by
 * {@code owner} (Casdoor JWT subject) AND domain-scoped by {@code domain} (the
 * validated-issuer brand). Every method takes the owner id so the SQL is always
 * owner-scoped, PLUS an optional {@code domain} predicate ({@link DomainScope}) so a
 * caller only ever touches a client in their OWN brand ({@code null} domain =
 * SUPERADMIN cross-domain bypass). The id is app-generated (UUID) so the INSERT is
 * portable (Postgres + H2) and returns the new row. {@code revoke} is
 * owner-AND-domain-AND-id scoped so a caller can never revoke another user's (or
 * brand's) client even with a guessed id.
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

    /** Back-compat overload — scopes to the platform {@code default} domain. */
    public Flux<ConnectedClient> listForOwner(String owner) {
        return listForOwner(owner, DomainRegistry.DEFAULT_DOMAIN);
    }

    /** Back-compat overload — scopes to the platform {@code default} domain. */
    public Mono<ConnectedClient> find(String owner, String id) {
        return find(owner, id, DomainRegistry.DEFAULT_DOMAIN);
    }

    /** Back-compat overload — stamps the platform {@code default} domain. */
    public Mono<ConnectedClient> record(String owner, String platform, String clientKind,
                                        String externalRef, String label) {
        return record(owner, platform, clientKind, externalRef, label, DomainRegistry.DEFAULT_DOMAIN);
    }

    /** Back-compat overload — scopes to the platform {@code default} domain. */
    public Mono<Long> revoke(String owner, String id) {
        return revoke(owner, id, DomainRegistry.DEFAULT_DOMAIN);
    }

    /** All of the owner's audited clients in their domain (own data only), newest
     *  first ({@code domain} null = SUPERADMIN cross-domain bypass). */
    public Flux<ConnectedClient> listForOwner(String owner, String domain) {
        var spec = db.sql("SELECT id, owner, platform, client_kind, external_ref, label, "
                        + "created_at, revoked_at FROM connected_client_audit "
                        + "WHERE owner = :owner" + DomainScope.andPredicate(domain)
                        + " ORDER BY created_at DESC, id")
                .bind("owner", owner);
        return DomainScope.bind(spec, domain).map(ConnectedClientAuditRepository::map).all();
    }

    /** The owner's audited client by id in their domain (own data only), or empty. */
    public Mono<ConnectedClient> find(String owner, String id, String domain) {
        var spec = db.sql("SELECT id, owner, platform, client_kind, external_ref, label, "
                        + "created_at, revoked_at FROM connected_client_audit "
                        + "WHERE owner = :owner AND id = :id" + DomainScope.andPredicate(domain))
                .bind("owner", owner).bind("id", id);
        return DomainScope.bind(spec, domain).map(ConnectedClientAuditRepository::map).first();
    }

    /**
     * Record an audit row for one of the owner's clients in their domain (app-generated
     * id) and return it. The domain is stamped server-side. Used both when the
     * homeserver list-seam surfaces a client we have no row for yet (record-on-observe)
     * and as the audit anchor a revoke later stamps.
     */
    public Mono<ConnectedClient> record(String owner, String platform, String clientKind,
                                        String externalRef, String label, String domain) {
        String id = UUID.randomUUID().toString();
        String dom = DomainScope.isUnscoped(domain) ? DomainRegistry.DEFAULT_DOMAIN : domain;
        return db.sql("INSERT INTO connected_client_audit "
                        + "(id, owner, platform, client_kind, external_ref, label, domain, created_at) "
                        + "VALUES (:id, :owner, :platform, :kind, :ref, :label, :dom, now())")
                .bind("id", id).bind("owner", owner).bind("platform", platform)
                .bind("kind", clientKind).bind("ref", externalRef)
                .bind("label", label == null ? "" : label)
                .bind("dom", dom)
                .fetch().rowsUpdated()
                .then(find(owner, id, domain));
    }

    /**
     * Stamp {@code revoked_at} on the owner's client (scoped by owner AND domain AND
     * id, and only when not already revoked) so a double-revoke is idempotent. Returns
     * the number of rows stamped (0 = nothing active for this owner+domain+id).
     */
    public Mono<Long> revoke(String owner, String id, String domain) {
        var spec = db.sql("UPDATE connected_client_audit SET revoked_at = now() "
                        + "WHERE owner = :owner AND id = :id AND revoked_at IS NULL"
                        + DomainScope.andPredicate(domain))
                .bind("owner", owner).bind("id", id);
        return DomainScope.bind(spec, domain).fetch().rowsUpdated();
    }
}
