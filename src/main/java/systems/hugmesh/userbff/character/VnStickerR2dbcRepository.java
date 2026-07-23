package systems.hugmesh.userbff.character;

import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * Reactive (R2DBC) store for {@code vn_sticker_pack}. Federation-idiom (mirrors
 * {@link VnCharacterPartR2dbcRepository}): DERIVED ordered finders (the owner-AND-domain
 * newest-first list, the owner-scoped single read-by-id) and an {@code @Query}
 * (static-final SQL constant) only for the INSERT that needs a server-side {@code now()}
 * {@code created_at} and the DB-generated id.
 *
 * <p>The {@code findByIdAndOwnerSubject} read is owner-scoped so a caller can never read
 * another user's sticker (a foreign id yields empty → the controller maps it to a 404, no
 * cross-owner existence leak).
 */
public interface VnStickerR2dbcRepository
        extends ReactiveCrudRepository<VnStickerEntity, String> {

    Flux<VnStickerEntity> findByOwnerSubjectAndDomainOrderByCreatedAtDesc(
            String ownerSubject, String domain);

    Flux<VnStickerEntity> findByOwnerSubjectOrderByCreatedAtDesc(String ownerSubject);

    /**
     * ACTIVE-ONLY owner finder (the MSC2545 pack-registration source): the owner's
     * stickers in a single lifecycle {@code status} ({@code ACTIVE}), newest first.
     * DERIVED (no raw SQL) — the registration service passes {@code status='ACTIVE'} so
     * only moderator-approved stickers are ever advertised in the {@code
     * im.ponies.user_emotes} pack. Owner-scoped: another subject's rows are unreachable.
     */
    Flux<VnStickerEntity> findByOwnerSubjectAndStatusOrderByCreatedAtDesc(
            String ownerSubject, String status);

    /** Owner-scoped single read (the serve path) — a foreign id yields empty. */
    Mono<VnStickerEntity> findByIdAndOwnerSubject(String id, String ownerSubject);

    // ---- INSERT (@Query — DB-generated id, server-side now()) ----

    // The id is OMITTED so Postgres fills it from its (gen_random_uuid())::text column
    // DEFAULT (changelog 017); RETURNING id reads the generated UUID string back. A plain
    // (non-@Modifying) @Query returning Mono<String>. status is a caller-supplied literal
    // ('PENDING' on save) so the row lands in the moderation queue.
    String INSERT_RETURNING_ID =
            "INSERT INTO vn_sticker_pack "
            + "(owner_subject, domain, expression, mxc_url, status, created_at) "
            + "VALUES (:ownerSubject, :domain, :expression, :mxcUrl, :status, now()) "
            + "RETURNING id";

    /** Plain INSERT ... RETURNING id — yields the DB-generated UUID string. */
    @Query(INSERT_RETURNING_ID)
    Mono<String> insertRowReturningId(@Param("ownerSubject") String ownerSubject,
                                      @Param("domain") String domain,
                                      @Param("expression") String expression,
                                      @Param("mxcUrl") String mxcUrl,
                                      @Param("status") String status);

    // ---- CAPTURE-AT-FILE: stamp the federation finding id back onto the row ----

    // Best-effort write-back of the federation @system finding id AFTER the row insert.
    // OWNER-SCOPED (defence-in-depth — a capture can only stamp the caller's own row).
    // Returns rows-affected. Mirrors VnCharacterPartR2dbcRepository.setFindingId.
    String SET_FINDING_ID =
            "UPDATE vn_sticker_pack SET finding_id = :findingId "
            + "WHERE id = :id AND owner_subject = :owner";

    @Modifying
    @Query(SET_FINDING_ID)
    Mono<Integer> setFindingId(@Param("id") String id,
                               @Param("owner") String owner,
                               @Param("findingId") Long findingId);

    // ---- STATUS FLIP: the moderation-receiver activation/rejection ----

    // Flip a PENDING row to ACTIVE/REJECTED. PENDING-GUARDED + idempotent: a second
    // resolve (or an already-resolved / unknown row) updates ZERO rows — a safe no-op.
    // status is a caller-validated lifecycle literal (exactly ACTIVE or REJECTED; the 017
    // CHECK constraint is the DB backstop). Mirrors the character-part flip.
    String FLIP_STATUS_WHERE_PENDING =
            "UPDATE vn_sticker_pack SET status = :status "
            + "WHERE id = :id AND status = 'PENDING'";

    @Modifying
    @Query(FLIP_STATUS_WHERE_PENDING)
    Mono<Integer> updateStatusByIdWherePending(@Param("id") String id,
                                               @Param("status") String status);
}
