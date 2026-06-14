package systems.snapdragon.userbff.notification;

import io.r2dbc.spi.Row;
import io.r2dbc.spi.RowMetadata;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.snapdragon.userbff.security.DomainRegistry;
import systems.snapdragon.userbff.security.DomainScope;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.UUID;

/**
 * Reactive (R2DBC) store for {@code user_notifications} — the always-on in-app FLOOR
 * inbox, owner-keyed by {@code user_subject} (Casdoor JWT subject) AND domain-scoped by
 * {@code domain} (the validated-issuer brand). Every read/mutate takes the owner id so
 * the SQL is always owner-scoped, PLUS an optional {@code domain} predicate
 * ({@link DomainScope}) so a caller can only ever read/mark-read their OWN
 * notifications in their OWN brand ({@code null} domain = SUPERADMIN cross-domain
 * bypass). Mirrors {@link systems.snapdragon.userbff.media.MediaPoisonDecisionRepository}.
 *
 * <p>SHIPS DARK in PR1: there is intentionally NO insert path here — the
 * snapdragon-actions reconciler in a later PR is the only writer. This repository is
 * the read + mark-read side. A package-private {@link #insertForTest} exists ONLY so
 * the slice tests can seed rows to prove the read/mark-read owner+domain isolation.
 */
@Repository
public class UserNotificationRepository {

    /** The server-side cap on a single inbox page — the read is always bounded so a
     *  caller can never pull an unbounded result set. */
    public static final int MAX_PAGE = 100;

    private final DatabaseClient db;

    public UserNotificationRepository(DatabaseClient db) {
        this.db = db;
    }

    private static Instant toInstant(Object raw) {
        return switch (raw) {
            case Instant i -> i;
            case LocalDateTime ldt -> ldt.toInstant(ZoneOffset.UTC);
            case OffsetDateTime odt -> odt.toInstant();
            case null, default -> null;
        };
    }

    private static UserNotification map(Row row, RowMetadata meta) {
        return new UserNotification(
                row.get("id", String.class),
                row.get("user_subject", String.class),
                row.get("category", String.class),
                row.get("title", String.class),
                row.get("body", String.class),
                toInstant(row.get("created_at")),
                toInstant(row.get("read_at")));
    }

    private static final String COLS =
            "id, user_subject, category, title, body, created_at, read_at";

    /** Back-compat overload — scopes to the platform {@code default} domain. */
    public Flux<UserNotification> listForOwner(String userSubject, int limit) {
        return listForOwner(userSubject, DomainRegistry.DEFAULT_DOMAIN, limit);
    }

    /**
     * The owner's in-app notifications in their domain (own data only), newest first,
     * capped at {@link #MAX_PAGE} ({@code domain} null = SUPERADMIN cross-domain
     * bypass). A non-positive or over-cap {@code limit} clamps into {@code [1, MAX_PAGE]}.
     */
    public Flux<UserNotification> listForOwner(String userSubject, String domain, int limit) {
        int cap = clamp(limit);
        var spec = db.sql("SELECT " + COLS + " FROM user_notifications "
                        + "WHERE user_subject = :uid" + DomainScope.andPredicate(domain)
                        + " ORDER BY created_at DESC, id LIMIT " + cap)
                .bind("uid", userSubject);
        return DomainScope.bind(spec, domain).map(UserNotificationRepository::map).all();
    }

    /** Back-compat overload — scopes to the platform {@code default} domain. */
    public Mono<Long> markRead(String id, String userSubject) {
        return markRead(id, userSubject, DomainRegistry.DEFAULT_DOMAIN);
    }

    /**
     * Mark ONE notification read for the owner in their domain. Owner-AND-domain-AND-id
     * scoped (and only if currently unread, so a re-mark is a no-op), so a caller can
     * NEVER mark another user's (or brand's) notification read even with a known id.
     * Returns the number of rows updated — 0 means the id is not the caller's own
     * owner+domain unread row (the service maps 0 → 404). {@code domain} null =
     * SUPERADMIN cross-domain bypass.
     */
    public Mono<Long> markRead(String id, String userSubject, String domain) {
        var spec = db.sql("UPDATE user_notifications SET read_at = now() "
                        + "WHERE id = :id AND user_subject = :uid" + DomainScope.andPredicate(domain)
                        + " AND read_at IS NULL")
                .bind("id", id).bind("uid", userSubject);
        return DomainScope.bind(spec, domain).fetch().rowsUpdated();
    }

    /**
     * INSERT-IF-ABSENT one delivered in-app notification keyed by the caller-supplied
     * DETERMINISTIC {@code id} (see {@link StableNotificationId}). The ONLY production
     * write path into {@code user_notifications} — reached ONLY by the service-principal
     * internal deliver endpoint (the snapdragon-actions reconciler). Idempotent by
     * construction: the {@code id} is derived from the source event, so a RETRY of the
     * same delivery presents the SAME id and the row already exists → no second row.
     *
     * <p>Portable (Postgres + H2): an existence check on the PK, then an INSERT only when
     * absent. The {@code id} is the {@code user_notifications} PRIMARY KEY, so even under
     * a concurrent double-call the second INSERT would hit a duplicate-key error rather
     * than write a second row — the existence pre-check makes the common (sequential
     * retry) path a clean no-op without surfacing an error.
     *
     * <p>Unlike the read/mark-read paths this takes the target {@code (domain,
     * userSubject)} EXPLICITLY (the service principal acts on behalf of the SYSTEM for a
     * named target, NOT owner==caller) — the {@code domain} is stamped verbatim, never a
     * SUPERADMIN-style bypass. {@code title}/{@code body} come from the caller (the
     * reconciler builds them); no actor identity is ever synthesised here.
     *
     * @return {@code true} iff a NEW row was inserted; {@code false} iff the id already
     *         existed (a deduped retry — no write performed).
     */
    public Mono<Boolean> insertIfAbsent(String id, String domain, String userSubject,
                                        String category, String title, String body) {
        return existsById(id).flatMap(exists -> {
            if (exists) {
                return Mono.just(false);                 // deduped retry — no second row
            }
            var spec = db.sql("INSERT INTO user_notifications "
                            + "(id, domain, user_subject, category, title, body, created_at) "
                            + "VALUES (:id, :dom, :uid, :cat, :title, :body, now())")
                    .bind("id", id).bind("dom", domain).bind("uid", userSubject)
                    .bind("cat", category).bind("title", title);
            spec = (body == null) ? spec.bindNull("body", String.class) : spec.bind("body", body);
            return spec.fetch().rowsUpdated().thenReturn(true);
        });
    }

    /** True iff a row with this PK id exists (any owner/domain) — the idempotency probe
     *  for {@link #insertIfAbsent}. The id is a server-derived deterministic hash, never
     *  caller-enumerable, so this is not an information-leak side channel (the deliver
     *  endpoint is service-principal-only). */
    public Mono<Boolean> existsById(String id) {
        return db.sql("SELECT 1 FROM user_notifications WHERE id = :id")
                .bind("id", id)
                .map((row, m) -> Boolean.TRUE).first().defaultIfEmpty(false);
    }

    /**
     * True iff a row with this id exists for the owner in their domain (regardless of
     * read state). Lets the service distinguish "already-read own row" (a no-op success)
     * from "not the caller's row" (a 404) after a 0-row {@link #markRead}. Owner+domain
     * scoped, so it never reveals another user's row exists.
     */
    public Mono<Boolean> existsForOwner(String id, String userSubject, String domain) {
        var spec = db.sql("SELECT 1 FROM user_notifications "
                        + "WHERE id = :id AND user_subject = :uid" + DomainScope.andPredicate(domain))
                .bind("id", id).bind("uid", userSubject);
        return DomainScope.bind(spec, domain).map((row, m) -> Boolean.TRUE).first().defaultIfEmpty(false);
    }

    private static int clamp(int limit) {
        if (limit < 1) return 1;
        return Math.min(limit, MAX_PAGE);
    }

    /**
     * TEST-ONLY seed of one notification row (PR1 ships dark — the real writer is the
     * later snapdragon-actions reconciler). Package-private + clearly named so it never
     * leaks into the production read/mark-read API surface; the slice tests use it to
     * prove owner+domain read isolation and the mark-read 404 boundary.
     */
    Mono<String> insertForTest(String userSubject, String category, String title,
                               String body, String domain) {
        String id = UUID.randomUUID().toString();
        String dom = DomainScope.isUnscoped(domain) ? DomainRegistry.DEFAULT_DOMAIN : domain;
        var spec = db.sql("INSERT INTO user_notifications "
                        + "(id, domain, user_subject, category, title, body, created_at) "
                        + "VALUES (:id, :dom, :uid, :cat, :title, :body, now())")
                .bind("id", id).bind("dom", dom).bind("uid", userSubject)
                .bind("cat", category).bind("title", title);
        spec = (body == null) ? spec.bindNull("body", String.class) : spec.bind("body", body);
        return spec.fetch().rowsUpdated().thenReturn(id);
    }
}
