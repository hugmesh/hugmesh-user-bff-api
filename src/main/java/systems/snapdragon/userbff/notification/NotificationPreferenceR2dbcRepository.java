package systems.snapdragon.userbff.notification;

import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * Reactive (R2DBC) store for {@code notification_preference}. Federation-idiom:
 * DERIVED ordered/single-row finders for the reads, and {@code @Query} (static-final
 * SQL constants) for the UPDATE-first/INSERT-if-absent upsert legs (server-side
 * {@code now()}).
 *
 * <p>SCOPED finders/updates carry {@code AND domain = :domain}; UNSCOPED omit it (the
 * SUPERADMIN cross-domain bypass). The {@code findAll} ordering ({@code ORDER BY
 * category}) is preserved by the {@code OrderByCategoryAsc} suffix.
 */
public interface NotificationPreferenceR2dbcRepository
        extends ReactiveCrudRepository<NotificationPreferenceEntity, String> {

    Flux<NotificationPreferenceEntity> findByUserSubjectOrderByCategoryAsc(String userSubject);

    Flux<NotificationPreferenceEntity> findByUserSubjectAndDomainOrderByCategoryAsc(
            String userSubject, String domain);

    Mono<NotificationPreferenceEntity> findByUserSubjectAndCategory(String userSubject, String category);

    Mono<NotificationPreferenceEntity> findByUserSubjectAndCategoryAndDomain(
            String userSubject, String category, String domain);

    // ---- UPSERT (@Query) ----

    String UPDATE_SCOPED =
            "UPDATE notification_preference SET enabled = :enabled, updated_at = now() "
            + "WHERE user_subject = :userSubject AND category = :category AND domain = :domain";

    String UPDATE_UNSCOPED =
            "UPDATE notification_preference SET enabled = :enabled, updated_at = now() "
            + "WHERE user_subject = :userSubject AND category = :category";

    String INSERT =
            "INSERT INTO notification_preference (domain, user_subject, category, enabled, updated_at) "
            + "VALUES (:domain, :userSubject, :category, :enabled, now())";

    @Modifying
    @Query(UPDATE_SCOPED)
    Mono<Long> updateScoped(@Param("userSubject") String userSubject, @Param("category") String category,
                            @Param("enabled") boolean enabled, @Param("domain") String domain);

    @Modifying
    @Query(UPDATE_UNSCOPED)
    Mono<Long> updateUnscoped(@Param("userSubject") String userSubject, @Param("category") String category,
                              @Param("enabled") boolean enabled);

    @Modifying
    @Query(INSERT)
    Mono<Long> insertRow(@Param("domain") String domain, @Param("userSubject") String userSubject,
                         @Param("category") String category, @Param("enabled") boolean enabled);
}
