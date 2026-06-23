package systems.snapdragon.userbff.notification;

import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * Reactive (R2DBC) store for {@code user_notifications}. Federation-idiom: the
 * inherited {@code existsById} reproduces the idempotency probe ({@code SELECT 1 WHERE
 * id = :id}); a DERIVED {@code existsBy...} reproduces the owner+domain existence
 * check; and {@code @Query} (static-final SQL constants) cover the bounded newest-first
 * inbox scan (a RUNTIME {@code LIMIT}, which a derived method cannot express), the
 * active-only {@code markRead} update ({@code read_at IS NULL} + {@code now()}), and the
 * INSERT (server-side {@code now()}, nullable {@code body}).
 *
 * <p>SCOPED variants carry {@code AND domain = :domain}; UNSCOPED omit it (SUPERADMIN
 * bypass).
 */
public interface UserNotificationR2dbcRepository
        extends ReactiveCrudRepository<UserNotificationEntity, String> {

    Mono<Boolean> existsByIdAndUserSubject(String id, String userSubject);

    Mono<Boolean> existsByIdAndUserSubjectAndDomain(String id, String userSubject, String domain);

    // ---- LIST (bounded newest-first scan; runtime LIMIT → @Query) ----

    String LIST_SCOPED =
            "SELECT id, domain, user_subject, category, title, body, created_at, read_at "
            + "FROM user_notifications WHERE user_subject = :userSubject AND domain = :domain "
            + "ORDER BY created_at DESC, id LIMIT :limit";

    String LIST_UNSCOPED =
            "SELECT id, domain, user_subject, category, title, body, created_at, read_at "
            + "FROM user_notifications WHERE user_subject = :userSubject "
            + "ORDER BY created_at DESC, id LIMIT :limit";

    @Query(LIST_SCOPED)
    Flux<UserNotificationEntity> listScoped(@Param("userSubject") String userSubject,
                                            @Param("domain") String domain, @Param("limit") int limit);

    @Query(LIST_UNSCOPED)
    Flux<UserNotificationEntity> listUnscoped(@Param("userSubject") String userSubject,
                                              @Param("limit") int limit);

    // ---- MARK-READ (active-only guard + server-side now()) ----

    String MARK_READ_SCOPED =
            "UPDATE user_notifications SET read_at = now() "
            + "WHERE id = :id AND user_subject = :userSubject AND domain = :domain AND read_at IS NULL";

    String MARK_READ_UNSCOPED =
            "UPDATE user_notifications SET read_at = now() "
            + "WHERE id = :id AND user_subject = :userSubject AND read_at IS NULL";

    @Modifying
    @Query(MARK_READ_SCOPED)
    Mono<Long> markReadScoped(@Param("id") String id, @Param("userSubject") String userSubject,
                              @Param("domain") String domain);

    @Modifying
    @Query(MARK_READ_UNSCOPED)
    Mono<Long> markReadUnscoped(@Param("id") String id, @Param("userSubject") String userSubject);

    // ---- INSERT (deterministic/caller-supplied id, nullable body, server-side now()) ----
    //
    // The PRODUCTION insertIfAbsent path supplies a DETERMINISTIC id explicitly for
    // idempotency (the existence pre-check is keyed on it), so this leg keeps the id
    // column/bind UNCHANGED — it is NOT DB-generated. A @Modifying row count as before.

    String INSERT =
            "INSERT INTO user_notifications (id, domain, user_subject, category, title, body, created_at) "
            + "VALUES (:id, :domain, :userSubject, :category, :title, :body, now())";

    @Modifying
    @Query(INSERT)
    Mono<Long> insertRow(@Param("id") String id, @Param("domain") String domain,
                         @Param("userSubject") String userSubject, @Param("category") String category,
                         @Param("title") String title, @Param("body") String body);

    // ---- INSERT (DB-generated id, nullable body, server-side now()) ----
    //
    // The id-OMITTED variant: Postgres fills id from its (gen_random_uuid())::text column
    // DEFAULT (changelog 015) and RETURNING id reads the generated UUID string back. Used
    // ONLY by the test-seed path (insertForTest) — the production deliver path keeps the
    // deterministic-id INSERT above. A plain (non-@Modifying) @Query returning Mono<String>.
    String INSERT_RETURNING_ID =
            "INSERT INTO user_notifications (domain, user_subject, category, title, body, created_at) "
            + "VALUES (:domain, :userSubject, :category, :title, :body, now()) "
            + "RETURNING id";

    /** Plain INSERT ... RETURNING id — yields the DB-generated UUID string. */
    @Query(INSERT_RETURNING_ID)
    Mono<String> insertRowReturningId(@Param("domain") String domain,
                                      @Param("userSubject") String userSubject,
                                      @Param("category") String category,
                                      @Param("title") String title, @Param("body") String body);
}
