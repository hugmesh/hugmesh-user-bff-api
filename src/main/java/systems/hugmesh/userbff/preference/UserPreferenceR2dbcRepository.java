package systems.hugmesh.userbff.preference;

import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * Reactive (R2DBC) store for {@code user_preference}. Federation-idiom: DERIVED
 * ordered finders for the reads, derived deletes, and {@code @Query} (static-final
 * SQL constants) for the UPDATE-first/INSERT-if-absent upsert legs that need
 * server-side {@code now()}.
 *
 * <p>SCOPED variants carry {@code AND domain = :domain}; UNSCOPED variants omit it
 * (the SUPERADMIN cross-domain bypass). The {@link UserPreferenceRepository} facade
 * picks the variant from a nullable {@code domain}. Ordering ({@code ORDER BY
 * pref_key}) is preserved by the derived {@code OrderByPrefKeyAsc} suffix.
 */
public interface UserPreferenceR2dbcRepository extends ReactiveCrudRepository<UserPreferenceEntity, String> {

    Flux<UserPreferenceEntity> findByUserIdOrderByPrefKeyAsc(String userId);

    Flux<UserPreferenceEntity> findByUserIdAndDomainOrderByPrefKeyAsc(String userId, String domain);

    Mono<UserPreferenceEntity> findByUserIdAndPrefKey(String userId, String prefKey);

    Mono<UserPreferenceEntity> findByUserIdAndPrefKeyAndDomain(String userId, String prefKey, String domain);

    Flux<UserPreferenceEntity> findByUserIdAndPrefValueOrderByPrefKeyAsc(String userId, String prefValue);

    Flux<UserPreferenceEntity> findByUserIdAndPrefValueAndDomainOrderByPrefKeyAsc(
            String userId, String prefValue, String domain);

    Mono<Long> deleteByUserIdAndPrefKey(String userId, String prefKey);

    Mono<Long> deleteByUserIdAndPrefKeyAndDomain(String userId, String prefKey, String domain);

    // ---- UPSERT (@Query) ----

    String UPDATE_SCOPED =
            "UPDATE user_preference SET pref_value = :value, updated_at = now() "
            + "WHERE user_id = :userId AND pref_key = :key AND domain = :domain";

    String UPDATE_UNSCOPED =
            "UPDATE user_preference SET pref_value = :value, updated_at = now() "
            + "WHERE user_id = :userId AND pref_key = :key";

    String INSERT =
            "INSERT INTO user_preference (user_id, pref_key, pref_value, domain, updated_at) "
            + "VALUES (:userId, :key, :value, :domain, now())";

    @Modifying
    @Query(UPDATE_SCOPED)
    Mono<Long> updateScoped(@Param("userId") String userId, @Param("key") String key,
                            @Param("value") String value, @Param("domain") String domain);

    @Modifying
    @Query(UPDATE_UNSCOPED)
    Mono<Long> updateUnscoped(@Param("userId") String userId, @Param("key") String key,
                              @Param("value") String value);

    @Modifying
    @Query(INSERT)
    Mono<Long> insertRow(@Param("userId") String userId, @Param("key") String key,
                         @Param("value") String value, @Param("domain") String domain);
}
