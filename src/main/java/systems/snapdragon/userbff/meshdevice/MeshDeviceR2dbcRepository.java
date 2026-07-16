package systems.snapdragon.userbff.meshdevice;

import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;

/**
 * Reactive (R2DBC) store for {@code mesh_device}. Federation-idiom: DERIVED finders /
 * deletes (the owner-AND-domain newest-first list, the owner-scoped single read, the
 * owner-scoped release, the bridge's active-rows export) and {@code @Query}
 * (static-final SQL constant) only for the INSERT that needs a server-side {@code now()}
 * {@code created_at} + the DB-generated id, and for the two STATE-GUARDED updates
 * (visibility, bridge status) whose {@code state = 'active'} predicate cannot be
 * expressed as a derived method.
 *
 * <p>The {@code findByIdAndOwnerSubject} read and both deletes are owner-scoped so a
 * caller can never touch a device that is not theirs (a foreign id yields empty/0 rows →
 * the controller maps that to a 404, no cross-owner existence leak).
 */
public interface MeshDeviceR2dbcRepository
        extends ReactiveCrudRepository<MeshDeviceEntity, String> {

    Flux<MeshDeviceEntity> findByOwnerSubjectAndDomainOrderByCreatedAtDesc(
            String ownerSubject, String domain);

    Flux<MeshDeviceEntity> findByOwnerSubjectOrderByCreatedAtDesc(String ownerSubject);

    /** Owner-scoped single read (the visibility-change diagnose path) — a foreign id
     *  yields empty. */
    Mono<MeshDeviceEntity> findByIdAndOwnerSubject(String id, String ownerSubject);

    /** The bridge export: every row in {@code state} (the caller passes {@code active})
     *  ACROSS owners and domains, oldest first (a stable order for the bridge poll). */
    Flux<MeshDeviceEntity> findByStateOrderByCreatedAtAsc(String state);

    /** Owner-scoped release (SUPERADMIN unscoped-domain leg). Rows deleted (0 or 1). */
    Mono<Long> deleteByIdAndOwnerSubject(String id, String ownerSubject);

    /** Owner-AND-domain-scoped release. Rows deleted (0 or 1). */
    Mono<Long> deleteByIdAndOwnerSubjectAndDomain(String id, String ownerSubject, String domain);

    // ---- INSERT (@Query — DB-generated id, nullable label, server-side now()) ----

    // The id is OMITTED so Postgres fills it from its (gen_random_uuid())::text column
    // DEFAULT (changelog 019, 015 idiom); RETURNING id reads the generated UUID string
    // back. visibility ('private'), state ('active') and every status/moderation column
    // are likewise OMITTED so the 019 column DEFAULTs / NULLs apply — a fresh claim is
    // always a private, active, not-yet-seen device. node_id is the service-CANONICALIZED
    // form; the 019 UNIQUE constraint on node_id alone makes a concurrent duplicate claim
    // a DuplicateKeyException (the service maps it to a 409).
    String INSERT_RETURNING_ID =
            "INSERT INTO mesh_device "
            + "(owner_subject, domain, node_id, label, created_at) "
            + "VALUES (:ownerSubject, :domain, :nodeId, :label, now()) "
            + "RETURNING id";

    /** Plain INSERT ... RETURNING id — yields the DB-generated UUID string. */
    @Query(INSERT_RETURNING_ID)
    Mono<String> insertRowReturningId(@Param("ownerSubject") String ownerSubject,
                                      @Param("domain") String domain,
                                      @Param("nodeId") String nodeId,
                                      @Param("label") String label);

    // ---- VISIBILITY (owner-managed, ACTIVE-guarded) ----

    // Owner-scoped + state-guarded: a foreign id, an unknown id, OR a REVOKED row all
    // update ZERO rows (the service then diagnoses 404 vs 409 with an owner-scoped read).
    // The guard makes "a revoked device's visibility cannot be changed" atomic — no
    // read-then-write race can slip a visibility change past a concurrent revocation.
    String SET_VISIBILITY_WHERE_ACTIVE =
            "UPDATE mesh_device SET visibility = :visibility "
            + "WHERE id = :id AND owner_subject = :owner AND state = 'active'";

    @Modifying
    @Query(SET_VISIBILITY_WHERE_ACTIVE)
    Mono<Integer> setVisibilityWhereActive(@Param("id") String id,
                                           @Param("owner") String owner,
                                           @Param("visibility") String visibility);

    // ---- BRIDGE STATUS (SERVICE-only writer, ACTIVE-guarded, keyed by node id) ----

    // The bridge reports status by NODE id (it has no row ids); only an ACTIVE row is
    // updated — an unknown node id or a revoked row updates ZERO rows (the fail-soft
    // "ignored" leg of the batch endpoint). All five fields are overwritten as one
    // report (a report is a snapshot, not a patch); the service clamps/normalizes the
    // values BEFORE this runs (the 019 battery CHECK is the DB backstop).
    String APPLY_STATUS_WHERE_ACTIVE =
            "UPDATE mesh_device SET last_seen_at = :lastSeenAt, battery_pct = :batteryPct, "
            + "snr = :snr, hops_away = :hopsAway, via_device = :viaDevice "
            + "WHERE node_id = :nodeId AND state = 'active'";

    @Modifying
    @Query(APPLY_STATUS_WHERE_ACTIVE)
    Mono<Integer> applyStatusWhereActive(@Param("nodeId") String nodeId,
                                         @Param("lastSeenAt") Instant lastSeenAt,
                                         @Param("batteryPct") Integer batteryPct,
                                         @Param("snr") Double snr,
                                         @Param("hopsAway") Integer hopsAway,
                                         @Param("viaDevice") String viaDevice);
}
