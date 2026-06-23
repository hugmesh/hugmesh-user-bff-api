package systems.snapdragon.userbff.block;

import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * Reactive (R2DBC) store for {@code user_block}. Federation-idiom: DERIVED ordered
 * finders ({@code findById} for the post-insert read-back, the owner-scoped newest-first
 * list) + derived deletes, and an {@code @Query} (static-final SQL constant) only for the
 * INSERT that needs a server-side {@code now()} {@code ts}.
 *
 * <p>The newest-first list preserves the original {@code ORDER BY ts DESC, id} via the
 * {@code OrderByTsDescIdAsc} suffix. SCOPED list/delete carry {@code AND domain =
 * :domain}; UNSCOPED omit it (SUPERADMIN bypass).
 *
 * <p>DB-GENERATED UUID PK (changelog 015): the {@code id} is NO LONGER minted in Java.
 * The {@code user_block.id} column carries a {@code (gen_random_uuid())::text} DEFAULT,
 * so the INSERT OMITS {@code id} and appends {@code RETURNING id} to read the
 * database-generated UUID string back. The INSERT is therefore a plain
 * (non-{@code @Modifying}) {@code @Query} returning {@code Mono<String>} (the new id),
 * NOT a {@code @Modifying} row count.
 */
public interface UserBlockR2dbcRepository extends ReactiveCrudRepository<UserBlockEntity, String> {

    Flux<UserBlockEntity> findByUserIdOrderByTsDescIdAsc(String userId);

    Flux<UserBlockEntity> findByUserIdAndDomainOrderByTsDescIdAsc(String userId, String domain);

    Mono<Long> deleteByUserIdAndId(String userId, String id);

    Mono<Long> deleteByUserIdAndIdAndDomain(String userId, String id, String domain);

    // ---- INSERT (@Query — DB-generated id + server-side now()) ----

    // The id is OMITTED so Postgres fills it from its (gen_random_uuid())::text column
    // DEFAULT (changelog 015); RETURNING id reads the generated UUID string back.
    String INSERT_RETURNING_ID =
            "INSERT INTO user_block (user_id, target, platform, domain, ts) "
            + "VALUES (:userId, :target, :platform, :domain, now()) "
            + "RETURNING id";

    /** Plain INSERT ... RETURNING id — yields the DB-generated UUID string. */
    @Query(INSERT_RETURNING_ID)
    Mono<String> insertRowReturningId(@Param("userId") String userId,
                                      @Param("target") String target,
                                      @Param("platform") String platform,
                                      @Param("domain") String domain);
}
