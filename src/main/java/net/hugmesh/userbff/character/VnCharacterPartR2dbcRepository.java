package net.hugmesh.userbff.character;

import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * Reactive (R2DBC) store for {@code vn_character_part}. Federation-idiom: DERIVED
 * ordered finders (the owner-AND-domain newest-first list, the owner-scoped single
 * read-by-id) and an {@code @Query} (static-final SQL constant) only for the INSERT
 * that needs a server-side {@code now()} {@code created_at} and the DB-generated id.
 *
 * <p>The {@code findByIdAndOwnerSubject} read is owner-scoped so the serve path can
 * never hand a part to a non-owner (a foreign id yields empty → the controller maps it
 * to a 404, no cross-owner existence leak).
 */
public interface VnCharacterPartR2dbcRepository
        extends ReactiveCrudRepository<VnCharacterPartEntity, String> {

    Flux<VnCharacterPartEntity> findByOwnerSubjectAndDomainOrderByCreatedAtDesc(
            String ownerSubject, String domain);

    Flux<VnCharacterPartEntity> findByOwnerSubjectOrderByCreatedAtDesc(String ownerSubject);

    /** Owner-scoped single read (the serve path) — a foreign id yields empty. */
    Mono<VnCharacterPartEntity> findByIdAndOwnerSubject(String id, String ownerSubject);

    // ---- INSERT (@Query — DB-generated id, nullable cols, server-side now()) ----

    // The id is OMITTED so Postgres fills it from its (gen_random_uuid())::text column
    // DEFAULT (changelog 016); RETURNING id reads the generated UUID string back. A plain
    // (non-@Modifying) @Query returning Mono<String>. status is a caller-supplied literal
    // ('PENDING' on save) so the row lands in the moderation queue.
    String INSERT_RETURNING_ID =
            "INSERT INTO vn_character_part "
            + "(owner_subject, domain, name, svg, status, head_archetype, created_at) "
            + "VALUES (:ownerSubject, :domain, :name, :svg, :status, :headArchetype, now()) "
            + "RETURNING id";

    /** Plain INSERT ... RETURNING id — yields the DB-generated UUID string. */
    @Query(INSERT_RETURNING_ID)
    Mono<String> insertRowReturningId(@Param("ownerSubject") String ownerSubject,
                                      @Param("domain") String domain,
                                      @Param("name") String name,
                                      @Param("svg") String svg,
                                      @Param("status") String status,
                                      @Param("headArchetype") String headArchetype);

    // ---- CAPTURE-AT-FILE: stamp the federation finding id back onto the row ----

    // Best-effort write-back of the federation @system finding id AFTER the row insert
    // (the row already exists; this links it to the finding it filed). OWNER-SCOPED so a
    // capture can only ever stamp the caller's OWN row (defence-in-depth — the id is the
    // freshly-inserted row's own id, but the owner predicate makes a cross-owner stamp
    // impossible even if the id were ever attacker-influenced). Returns rows-affected.
    String SET_FINDING_ID =
            "UPDATE vn_character_part SET finding_id = :findingId "
            + "WHERE id = :id AND owner_subject = :owner";

    @Modifying
    @Query(SET_FINDING_ID)
    Mono<Integer> setFindingId(@Param("id") String id,
                               @Param("owner") String owner,
                               @Param("findingId") Long findingId);

    // ---- STATUS FLIP: the moderation-receiver activation/rejection ----

    // Flip a PENDING row to ACTIVE/REJECTED. PENDING-GUARDED + idempotent: the
    // WHERE status='PENDING' predicate means a second resolve (or an already-resolved /
    // unknown row) updates ZERO rows — a safe no-op the receiver maps to a 404/no-op.
    // status is a caller-supplied lifecycle literal the controller has already validated
    // to be exactly ACTIVE or REJECTED (the 016 CHECK constraint is the DB backstop).
    String FLIP_STATUS_WHERE_PENDING =
            "UPDATE vn_character_part SET status = :status "
            + "WHERE id = :id AND status = 'PENDING'";

    @Modifying
    @Query(FLIP_STATUS_WHERE_PENDING)
    Mono<Integer> updateStatusByIdWherePending(@Param("id") String id,
                                               @Param("status") String status);
}
