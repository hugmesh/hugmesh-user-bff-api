package net.hugmesh.userbff.media;

import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * Reactive (R2DBC) store for {@code media_poison_decision}. Federation-idiom: DERIVED
 * ordered finders ({@code findById} read-back; the owner-scoped newest-first list; the
 * newest-by-ref {@code findFirst...} that reproduces {@code ORDER BY created_at DESC,
 * id LIMIT 1}) and an {@code @Query} (static-final SQL constant) only for the INSERT
 * that needs a server-side {@code now()} {@code created_at} with nullable
 * {@code media_ref}/{@code backend}.
 *
 * <p>SCOPED finders carry {@code AND domain = :domain}; UNSCOPED omit it (SUPERADMIN
 * bypass).
 */
public interface MediaPoisonDecisionR2dbcRepository
        extends ReactiveCrudRepository<MediaPoisonDecisionEntity, String> {

    Flux<MediaPoisonDecisionEntity> findByUserIdOrderByCreatedAtDescIdAsc(String userId);

    Flux<MediaPoisonDecisionEntity> findByUserIdAndDomainOrderByCreatedAtDescIdAsc(
            String userId, String domain);

    /** Newest decision for a ref — reproduces {@code ORDER BY created_at DESC, id LIMIT 1}. */
    Mono<MediaPoisonDecisionEntity> findFirstByUserIdAndMediaRefOrderByCreatedAtDescIdAsc(
            String userId, String mediaRef);

    Mono<MediaPoisonDecisionEntity> findFirstByUserIdAndMediaRefAndDomainOrderByCreatedAtDescIdAsc(
            String userId, String mediaRef, String domain);

    // ---- INSERT (@Query — DB-generated id, nullable cols, server-side now()) ----

    // The id is OMITTED so Postgres fills it from its (gen_random_uuid())::text column
    // DEFAULT (changelog 015); RETURNING id reads the generated UUID string back. A plain
    // (non-@Modifying) @Query returning Mono<String>.
    String INSERT_RETURNING_ID =
            "INSERT INTO media_poison_decision "
            + "(user_id, platform, media_ref, mode, status, backend, domain, created_at) "
            + "VALUES (:userId, :platform, :mediaRef, :mode, :status, :backend, :domain, now()) "
            + "RETURNING id";

    /** Plain INSERT ... RETURNING id — yields the DB-generated UUID string. */
    @Query(INSERT_RETURNING_ID)
    Mono<String> insertRowReturningId(@Param("userId") String userId,
                                      @Param("platform") String platform,
                                      @Param("mediaRef") String mediaRef,
                                      @Param("mode") String mode, @Param("status") String status,
                                      @Param("backend") String backend, @Param("domain") String domain);
}
