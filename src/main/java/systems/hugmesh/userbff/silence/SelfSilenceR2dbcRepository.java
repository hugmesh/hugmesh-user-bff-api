package systems.hugmesh.userbff.silence;

import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.LocalDateTime;

/**
 * Reactive (R2DBC) store for {@code self_silence}. Federation-idiom: DERIVED finders
 * for the single-row read + the overdue-sweep work list, and {@code @Query}
 * (static-final SQL constants) for the UPDATE-first/INSERT-if-absent activate legs +
 * the clear updates (all need server-side {@code now()} and the {@code cleared_at IS
 * NULL} active-only guard that a derived method cannot express).
 *
 * <p>SCOPED activate/clear carry {@code AND domain = :domain}; UNSCOPED omit it
 * (SUPERADMIN bypass). The SYSTEM clear is deliberately domain-unscoped (the expiry
 * sweep is a platform task).
 */
public interface SelfSilenceR2dbcRepository extends ReactiveCrudRepository<SelfSilenceEntity, String> {

    Mono<SelfSilenceEntity> findByUserId(String userId);

    Mono<SelfSilenceEntity> findByUserIdAndDomain(String userId, String domain);

    /** The scheduled wake's work list: active ({@code cleared_at IS NULL}) silences
     *  whose {@code expires_at <= asOf}, oldest-expiry first. Reproduces the original
     *  {@code WHERE cleared_at IS NULL AND expires_at <= :asOf ORDER BY expires_at}. */
    Flux<SelfSilenceEntity> findByClearedAtIsNullAndExpiresAtLessThanEqualOrderByExpiresAtAsc(
            LocalDateTime asOf);

    // ---- ACTIVATE (UPDATE-first / INSERT-if-absent) ----

    String UPDATE_SCOPED =
            "UPDATE self_silence SET started_at = now(), expires_at = :exp, cleared_at = NULL, "
            + "reason = :reason, updated_at = now() "
            + "WHERE user_id = :userId AND domain = :domain";

    String UPDATE_UNSCOPED =
            "UPDATE self_silence SET started_at = now(), expires_at = :exp, cleared_at = NULL, "
            + "reason = :reason, updated_at = now() "
            + "WHERE user_id = :userId";

    String INSERT =
            "INSERT INTO self_silence "
            + "(user_id, started_at, expires_at, cleared_at, reason, domain, updated_at) "
            + "VALUES (:userId, now(), :exp, NULL, :reason, :domain, now())";

    // ---- CLEAR (active-only guard) ----

    String CLEAR_SCOPED =
            "UPDATE self_silence SET cleared_at = now(), updated_at = now() "
            + "WHERE user_id = :userId AND cleared_at IS NULL AND domain = :domain";

    String CLEAR_UNSCOPED =
            "UPDATE self_silence SET cleared_at = now(), updated_at = now() "
            + "WHERE user_id = :userId AND cleared_at IS NULL";

    @Modifying
    @Query(UPDATE_SCOPED)
    Mono<Long> activateUpdateScoped(@Param("userId") String userId, @Param("domain") String domain,
                                    @Param("exp") LocalDateTime exp, @Param("reason") String reason);

    @Modifying
    @Query(UPDATE_UNSCOPED)
    Mono<Long> activateUpdateUnscoped(@Param("userId") String userId,
                                      @Param("exp") LocalDateTime exp, @Param("reason") String reason);

    @Modifying
    @Query(INSERT)
    Mono<Long> insertRow(@Param("userId") String userId, @Param("exp") LocalDateTime exp,
                         @Param("reason") String reason, @Param("domain") String domain);

    @Modifying
    @Query(CLEAR_SCOPED)
    Mono<Long> clearScoped(@Param("userId") String userId, @Param("domain") String domain);

    @Modifying
    @Query(CLEAR_UNSCOPED)
    Mono<Long> clearUnscoped(@Param("userId") String userId);
}
