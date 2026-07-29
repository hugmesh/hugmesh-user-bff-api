package systems.hugmesh.userbff.meshdevice;

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
 *
 * <p>The MODERATION members ({@code findForModeration*}, {@code revokeWhereActive*},
 * {@code restoreWhereRevoked*}) are the SERVICE-gated moderator surface: they are
 * deliberately NOT owner-scoped (a moderator acts across owners) but ARE brand-scoped in
 * their {@code *InDomain} variants, and both state writes are CAS statements whose
 * {@code state = '...'} predicate makes the transition atomic — never a read-then-write.
 */
public interface MeshDeviceR2dbcRepository
        extends ReactiveCrudRepository<MeshDeviceEntity, String> {

    Flux<MeshDeviceEntity> findByOwnerSubjectAndDomainOrderByCreatedAtDesc(
            String ownerSubject, String domain);

    Flux<MeshDeviceEntity> findByOwnerSubjectOrderByCreatedAtDesc(String ownerSubject);

    /** Owner-scoped single read (the visibility-change diagnose path) — a foreign id
     *  yields empty. */
    Mono<MeshDeviceEntity> findByIdAndOwnerSubject(String id, String ownerSubject);

    /** BRAND-scoped single read (the moderator diagnose path) — a row in another brand
     *  yields empty, so a branded moderator's 409-vs-404 diagnosis can never confirm the
     *  existence of another brand's device. */
    Mono<MeshDeviceEntity> findByIdAndDomain(String id, String domain);

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

    // ---- MODERATION CONSOLE LIST (SERVICE-only, BOUNDED, cross-owner) ----

    // The moderator console read spans EVERY owner (that is the point of a moderation
    // list), so it is bounded the way mod-bff's own audit reads are: an explicit
    // ORDER BY created_at DESC LIMIT :limit that the facade/service clamps, so a console
    // page can never stream the whole mesh_device table into memory. Derivation cannot
    // express a parameterized LIMIT, hence the static-final @Query constants — and the
    // optional state/domain filters are FOUR separate statements rather than one
    // ":x IS NULL OR ..." statement, mirroring ModActionR2dbcRepository's four bounded
    // audit finders (a Postgres bind of an untyped NULL in a comparison is exactly the
    // "could not determine data type of parameter" trap that pattern avoids).

    /** UNFILTERED, newest-claim-first, CAPPED (the cross-domain SUPERADMIN console). */
    String SELECT_FOR_MODERATION_NEWEST_LIMIT = """
            SELECT * FROM mesh_device \
            ORDER BY created_at DESC \
            LIMIT :limit""";

    /** By moderation STATE ({@code active}|{@code revoked}), newest first, CAPPED. */
    String SELECT_FOR_MODERATION_BY_STATE_NEWEST_LIMIT = """
            SELECT * FROM mesh_device \
            WHERE state = :state \
            ORDER BY created_at DESC \
            LIMIT :limit""";

    /** BRAND-scoped, newest first, CAPPED (a per-brand moderator's console). */
    String SELECT_FOR_MODERATION_BY_DOMAIN_NEWEST_LIMIT = """
            SELECT * FROM mesh_device \
            WHERE domain = :domain \
            ORDER BY created_at DESC \
            LIMIT :limit""";

    /** BRAND-scoped AND state-filtered, newest first, CAPPED. */
    String SELECT_FOR_MODERATION_BY_STATE_AND_DOMAIN_NEWEST_LIMIT = """
            SELECT * FROM mesh_device \
            WHERE state = :state AND domain = :domain \
            ORDER BY created_at DESC \
            LIMIT :limit""";

    @Query(SELECT_FOR_MODERATION_NEWEST_LIMIT)
    Flux<MeshDeviceEntity> findForModerationNewest(@Param("limit") int limit);

    @Query(SELECT_FOR_MODERATION_BY_STATE_NEWEST_LIMIT)
    Flux<MeshDeviceEntity> findForModerationByStateNewest(@Param("state") String state,
                                                          @Param("limit") int limit);

    @Query(SELECT_FOR_MODERATION_BY_DOMAIN_NEWEST_LIMIT)
    Flux<MeshDeviceEntity> findForModerationByDomainNewest(@Param("domain") String domain,
                                                           @Param("limit") int limit);

    @Query(SELECT_FOR_MODERATION_BY_STATE_AND_DOMAIN_NEWEST_LIMIT)
    Flux<MeshDeviceEntity> findForModerationByStateAndDomainNewest(@Param("state") String state,
                                                                   @Param("domain") String domain,
                                                                   @Param("limit") int limit);

    // ---- MODERATION STATE WRITES (SERVICE-only, CAS on state) ----

    // Both writes are COMPARE-AND-SET at the SQL layer, exactly like
    // SET_VISIBILITY_WHERE_ACTIVE: the source state is a WHERE predicate, so the
    // transition is atomic and a zero-row result is then DIAGNOSED by a read (404 unknown
    // vs 409 wrong state) — never a read-then-write, which two concurrent moderators (or
    // a moderator racing the owner's own visibility change) could interleave. The
    // *_IN_DOMAIN variants add the brand predicate for a per-brand moderator; the
    // unscoped pair is the cross-domain SUPERADMIN leg (same null-domain convention as
    // this repository's delete/list).

    // revoked_at is stamped SERVER-side with now() (never a caller-supplied clock);
    // revoked_by/revoke_reason carry the moderator identity + the user-facing reason.
    String REVOKE_WHERE_ACTIVE = """
            UPDATE mesh_device \
            SET state = 'revoked', revoked_by = :moderator, revoked_at = now(), \
                revoke_reason = :reason \
            WHERE id = :id AND state = 'active'""";

    String REVOKE_WHERE_ACTIVE_IN_DOMAIN = """
            UPDATE mesh_device \
            SET state = 'revoked', revoked_by = :moderator, revoked_at = now(), \
                revoke_reason = :reason \
            WHERE id = :id AND domain = :domain AND state = 'active'""";

    // The restore CLEARS the whole audit trio: a restored device must not keep showing
    // the owner a stale revoke reason (the 'why' is preserved in mod-bff's mod_action
    // ledger, which is the durable moderation record — this table only carries the
    // CURRENT state).
    String RESTORE_WHERE_REVOKED = """
            UPDATE mesh_device \
            SET state = 'active', revoked_by = NULL, revoked_at = NULL, \
                revoke_reason = NULL \
            WHERE id = :id AND state = 'revoked'""";

    String RESTORE_WHERE_REVOKED_IN_DOMAIN = """
            UPDATE mesh_device \
            SET state = 'active', revoked_by = NULL, revoked_at = NULL, \
                revoke_reason = NULL \
            WHERE id = :id AND domain = :domain AND state = 'revoked'""";

    @Modifying
    @Query(REVOKE_WHERE_ACTIVE)
    Mono<Integer> revokeWhereActive(@Param("id") String id,
                                    @Param("moderator") String moderator,
                                    @Param("reason") String reason);

    @Modifying
    @Query(REVOKE_WHERE_ACTIVE_IN_DOMAIN)
    Mono<Integer> revokeWhereActiveInDomain(@Param("id") String id,
                                            @Param("domain") String domain,
                                            @Param("moderator") String moderator,
                                            @Param("reason") String reason);

    @Modifying
    @Query(RESTORE_WHERE_REVOKED)
    Mono<Integer> restoreWhereRevoked(@Param("id") String id);

    @Modifying
    @Query(RESTORE_WHERE_REVOKED_IN_DOMAIN)
    Mono<Integer> restoreWhereRevokedInDomain(@Param("id") String id,
                                              @Param("domain") String domain);
}
