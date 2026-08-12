package net.hugmesh.userbff.client;

import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * Reactive (R2DBC) store for {@code connected_client_audit}. Federation-idiom: DERIVED
 * ordered/single-row finders for the list + by-id reads, and {@code @Query}
 * (static-final SQL constants) for the INSERT (server-side {@code now()}) and the
 * active-only {@code revoke} update ({@code revoked_at IS NULL} guard + {@code now()}).
 *
 * <p>SCOPED variants carry {@code AND domain = :domain}; UNSCOPED omit it (SUPERADMIN
 * bypass). The list ordering ({@code ORDER BY created_at DESC, id}) is preserved by the
 * {@code OrderByCreatedAtDescIdAsc} suffix.
 */
public interface ConnectedClientAuditR2dbcRepository
        extends ReactiveCrudRepository<ConnectedClientAuditEntity, String> {

    Flux<ConnectedClientAuditEntity> findByOwnerOrderByCreatedAtDescIdAsc(String owner);

    Flux<ConnectedClientAuditEntity> findByOwnerAndDomainOrderByCreatedAtDescIdAsc(
            String owner, String domain);

    Mono<ConnectedClientAuditEntity> findByOwnerAndId(String owner, String id);

    Mono<ConnectedClientAuditEntity> findByOwnerAndIdAndDomain(String owner, String id, String domain);

    // ---- INSERT (DB-generated id, server-side now()) ----

    // The id is OMITTED so Postgres fills it from its (gen_random_uuid())::text column
    // DEFAULT (changelog 015); RETURNING id reads the generated UUID string back. The
    // INSERT is therefore a plain (non-@Modifying) @Query returning Mono<String>.
    String INSERT_RETURNING_ID =
            "INSERT INTO connected_client_audit "
            + "(owner, platform, client_kind, external_ref, label, domain, created_at) "
            + "VALUES (:owner, :platform, :clientKind, :externalRef, :label, :domain, now()) "
            + "RETURNING id";

    /** Plain INSERT ... RETURNING id — yields the DB-generated UUID string. */
    @Query(INSERT_RETURNING_ID)
    Mono<String> insertRowReturningId(@Param("owner") String owner,
                                      @Param("platform") String platform,
                                      @Param("clientKind") String clientKind,
                                      @Param("externalRef") String externalRef,
                                      @Param("label") String label,
                                      @Param("domain") String domain);

    // ---- REVOKE (active-only guard + server-side now()) ----

    String REVOKE_SCOPED =
            "UPDATE connected_client_audit SET revoked_at = now() "
            + "WHERE owner = :owner AND id = :id AND revoked_at IS NULL AND domain = :domain";

    String REVOKE_UNSCOPED =
            "UPDATE connected_client_audit SET revoked_at = now() "
            + "WHERE owner = :owner AND id = :id AND revoked_at IS NULL";

    @Modifying
    @Query(REVOKE_SCOPED)
    Mono<Long> revokeScoped(@Param("owner") String owner, @Param("id") String id,
                            @Param("domain") String domain);

    @Modifying
    @Query(REVOKE_UNSCOPED)
    Mono<Long> revokeUnscoped(@Param("owner") String owner, @Param("id") String id);
}
