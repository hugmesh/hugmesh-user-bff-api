package systems.snapdragon.userbff.client;

import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.snapdragon.userbff.security.DomainRegistry;
import systems.snapdragon.userbff.security.DomainScope;

import java.util.UUID;

/**
 * Owner-AND-domain-scoped facade over {@link ConnectedClientAuditR2dbcRepository} for
 * {@code connected_client_audit}. Keeps the original method surface ({@code listForOwner}
 * / {@code find} / {@code record} / {@code revoke}, with the {@code default}-domain
 * back-compat overloads) so the connected-clients service and slice tests are unchanged;
 * all data access now flows through the reactive repository interface (no raw
 * {@code DatabaseClient SQL}).
 */
@Repository
public class ConnectedClientAuditRepository {

    private final ConnectedClientAuditR2dbcRepository repo;

    public ConnectedClientAuditRepository(ConnectedClientAuditR2dbcRepository repo) {
        this.repo = repo;
    }

    private static ConnectedClient toWire(ConnectedClientAuditEntity e) {
        return new ConnectedClient(
                e.id(), e.owner(), e.platform(), e.clientKind(), e.externalRef(),
                e.label(), e.createdAt(), e.revokedAt());
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
        var rows = DomainScope.isUnscoped(domain)
                ? repo.findByOwnerOrderByCreatedAtDescIdAsc(owner)
                : repo.findByOwnerAndDomainOrderByCreatedAtDescIdAsc(owner, domain);
        return rows.map(ConnectedClientAuditRepository::toWire);
    }

    /** The owner's audited client by id in their domain (own data only), or empty. */
    public Mono<ConnectedClient> find(String owner, String id, String domain) {
        var found = DomainScope.isUnscoped(domain)
                ? repo.findByOwnerAndId(owner, id)
                : repo.findByOwnerAndIdAndDomain(owner, id, domain);
        return found.map(ConnectedClientAuditRepository::toWire);
    }

    /**
     * Record an audit row for one of the owner's clients in their domain (app-generated
     * id) and return it. The domain is stamped server-side.
     */
    public Mono<ConnectedClient> record(String owner, String platform, String clientKind,
                                        String externalRef, String label, String domain) {
        String id = UUID.randomUUID().toString();
        String dom = DomainScope.isUnscoped(domain) ? DomainRegistry.DEFAULT_DOMAIN : domain;
        return repo.insertRow(id, owner, platform, clientKind, externalRef,
                        label == null ? "" : label, dom)
                .then(find(owner, id, domain));
    }

    /**
     * Stamp {@code revoked_at} on the owner's client (scoped by owner AND domain AND id,
     * and only when not already revoked) so a double-revoke is idempotent. Returns the
     * number of rows stamped (0 = nothing active for this owner+domain+id).
     */
    public Mono<Long> revoke(String owner, String id, String domain) {
        return DomainScope.isUnscoped(domain)
                ? repo.revokeUnscoped(owner, id)
                : repo.revokeScoped(owner, id, domain);
    }
}
