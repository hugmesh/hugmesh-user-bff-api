package net.hugmesh.userbff.prefstore;

import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * Reactive (R2DBC) store for {@code user_preferences_store}. Federation-idiom: DERIVED
 * ordered finders + deletes, and {@code @Query} (static-final SQL constants) only for
 * the UPDATE-first/INSERT-if-absent upsert legs (server-side {@code now()}).
 *
 * <p>SCOPED variants carry {@code AND domain = :domain}; UNSCOPED variants omit it (the
 * SUPERADMIN cross-domain bypass). Ordering ({@code ORDER BY pref_key}) is preserved by
 * the {@code OrderByPrefKeyAsc} suffix.
 */
public interface UserPreferencesStoreR2dbcRepository
        extends ReactiveCrudRepository<UserPreferencesStoreEntity, String> {

    Flux<UserPreferencesStoreEntity> findByUserIdOrderByPrefKeyAsc(String userId);

    Flux<UserPreferencesStoreEntity> findByUserIdAndDomainOrderByPrefKeyAsc(String userId, String domain);

    Mono<UserPreferencesStoreEntity> findByUserIdAndPrefKey(String userId, String prefKey);

    Mono<UserPreferencesStoreEntity> findByUserIdAndPrefKeyAndDomain(String userId, String prefKey, String domain);

    Mono<Long> deleteByUserIdAndPrefKey(String userId, String prefKey);

    Mono<Long> deleteByUserIdAndPrefKeyAndDomain(String userId, String prefKey, String domain);

    // ---- UPSERT (@Query) ----

    String UPDATE_SCOPED =
            "UPDATE user_preferences_store SET pref_value = :value, updated_at = now() "
            + "WHERE user_id = :userId AND pref_key = :key AND domain = :domain";

    String UPDATE_UNSCOPED =
            "UPDATE user_preferences_store SET pref_value = :value, updated_at = now() "
            + "WHERE user_id = :userId AND pref_key = :key";

    String INSERT =
            "INSERT INTO user_preferences_store (user_id, pref_key, pref_value, domain, updated_at) "
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
