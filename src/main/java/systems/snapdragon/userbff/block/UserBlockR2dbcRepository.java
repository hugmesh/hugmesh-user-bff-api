package systems.snapdragon.userbff.block;

import org.springframework.data.r2dbc.repository.Modifying;
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
 */
public interface UserBlockR2dbcRepository extends ReactiveCrudRepository<UserBlockEntity, String> {

    Flux<UserBlockEntity> findByUserIdOrderByTsDescIdAsc(String userId);

    Flux<UserBlockEntity> findByUserIdAndDomainOrderByTsDescIdAsc(String userId, String domain);

    Mono<Long> deleteByUserIdAndId(String userId, String id);

    Mono<Long> deleteByUserIdAndIdAndDomain(String userId, String id, String domain);

    // ---- INSERT (@Query — app-assigned id + server-side now()) ----

    String INSERT =
            "INSERT INTO user_block (id, user_id, target, platform, domain, ts) "
            + "VALUES (:id, :userId, :target, :platform, :domain, now())";

    @Modifying
    @Query(INSERT)
    Mono<Long> insertRow(@Param("id") String id, @Param("userId") String userId,
                         @Param("target") String target, @Param("platform") String platform,
                         @Param("domain") String domain);
}
