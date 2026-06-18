package systems.snapdragon.userbff.silence;

import io.r2dbc.spi.Row;
import io.r2dbc.spi.RowMetadata;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.util.retry.Retry;
import systems.snapdragon.userbff.security.DomainRegistry;
import systems.snapdragon.userbff.security.DomainScope;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;

/**
 * Reactive (R2DBC) store for {@code self_silence} — owner-keyed by {@code user_id}
 * (Casdoor JWT subject) AND domain-scoped by {@code domain} (the validated-issuer
 * brand). A user has at most one row (PK on {@code user_id}); every user-facing
 * method is owner-scoped PLUS an optional {@code domain} predicate
 * ({@link DomainScope}) so a caller can only touch their OWN silence in their OWN
 * brand ({@code null} domain = SUPERADMIN cross-domain bypass).
 *
 * <p>The row is the source of truth and {@code expires_at} is authoritative. The
 * scheduled wake uses {@link #findOverdueActive(Instant)} to re-select expired-but-
 * uncleared rows ACROSS ALL brands (the expiry sweep is a system task, not a
 * per-principal read — it auto-clears every overdue silence regardless of tenant)
 * and the system-scoped {@link #clearSystem(String)} to stamp {@code cleared_at}.
 * {@code DELETE}-free clearing keeps the audit history of a user's self-silences.
 */
@Repository
public class SelfSilenceRepository {

    private final DatabaseClient db;

    public SelfSilenceRepository(DatabaseClient db) {
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

    private static SelfSilence map(Row row, RowMetadata meta) {
        return new SelfSilence(
                row.get("user_id", String.class),
                toInstant(row.get("started_at")),
                toInstant(row.get("expires_at")),
                toInstant(row.get("cleared_at")),
                row.get("reason", String.class),
                toInstant(row.get("updated_at")));
    }

    /** Back-compat overload — scopes to the platform {@code default} domain. */
    public Mono<SelfSilence> find(String userId) {
        return find(userId, DomainRegistry.DEFAULT_DOMAIN);
    }

    /** Back-compat overload — stamps/operates on the platform {@code default} domain. */
    public Mono<SelfSilence> activate(String userId, Instant expiresAt, String reason) {
        return activate(userId, expiresAt, reason, DomainRegistry.DEFAULT_DOMAIN);
    }

    /** Back-compat overload — scopes to the platform {@code default} domain. */
    public Mono<Long> clear(String userId) {
        return clear(userId, DomainRegistry.DEFAULT_DOMAIN);
    }

    /** The owner's current silence row (active or cleared) within their domain, or
     *  empty if none ever ({@code domain} null = SUPERADMIN cross-domain bypass). */
    public Mono<SelfSilence> find(String userId, String domain) {
        var spec = db.sql("SELECT user_id, started_at, expires_at, cleared_at, reason, updated_at "
                        + "FROM self_silence WHERE user_id = :uid" + DomainScope.andPredicate(domain))
                .bind("uid", userId);
        return DomainScope.bind(spec, domain).map(SelfSilenceRepository::map).first();
    }

    /** Bound on the upsert's lose-the-INSERT-race retries (see {@link #activate}).
     *  A handful is ample: each retry only happens when a CONCURRENT peer won the
     *  INSERT for the SAME single-row PK, after which the retry's UPDATE-first path
     *  always finds the row and succeeds — there is no unbounded contention. */
    private static final long UPSERT_MAX_RETRIES = 8;

    /**
     * Activate (or re-activate) the owner's silence in their domain: upsert a row with
     * the given window/reason and a NULL {@code cleared_at}, starting a clean active
     * window. ATOMIC/IDEMPOTENT and PORTABLE (Postgres + H2): UPDATE-first (owner AND
     * domain scoped), INSERT only if absent (the domain is stamped server-side) — the
     * UPDATE-first/INSERT-if-absent shape MIRRORS
     * {@link systems.snapdragon.userbff.notification.NotificationPreferenceRepository#upsert},
     * HARDENED with a duplicate-key retry to also close the concurrent-first-INSERT
     * window (see below).
     *
     * <p>This deliberately replaces the former DELETE-then-INSERT (two unguarded
     * statements against a {@code user_id}-only PK): two CONCURRENT same-subject
     * activations could interleave DELETE/DELETE then INSERT/INSERT and trip the PK with
     * a {@code 23505} unique violation surfacing as a 500 ({@code ApiExceptionHandler}
     * has no duplicate-key handler). The self-silence is owner-only ({@code owner ==
     * subject}), so a single user CAN race themselves (double-tap / retry). The
     * UPDATE-first form makes a re-activate a no-409 in-place overwrite: it re-stamps
     * {@code started_at = now()} (a fresh window, preserving the old DELETE-then-INSERT
     * semantics), the new window/reason/domain and clears {@code cleared_at}. The UPDATE
     * is owner+domain scoped; the INSERT (when absent) stamps the domain server-side.
     * Returns the freshly-written row.
     *
     * <p><b>Concurrent-first-INSERT window.</b> UPDATE-first/INSERT-if-absent is NOT
     * atomic on its own: two activations for a brand-new subject can BOTH UPDATE zero
     * rows and BOTH attempt the INSERT, so the loser hits a unique violation. Rather than
     * a non-portable {@code INSERT ... ON CONFLICT} (Postgres-only) or a heavier
     * serialized transaction, the whole upsert is wrapped in a bounded
     * {@code retryWhen(DuplicateKeyException)}: on the (rare, single-row) collision the
     * retry's UPDATE finds the now-present row and succeeds. Net effect on BOTH engines
     * — {@code activate} is idempotent and never surfaces a 23505/500.
     */
    public Mono<SelfSilence> activate(String userId, Instant expiresAt, String reason, String domain) {
        String dom = DomainScope.isUnscoped(domain) ? DomainRegistry.DEFAULT_DOMAIN : domain;
        var exp = LocalDateTime.ofInstant(expiresAt, ZoneOffset.UTC);
        String safeReason = reason == null ? "" : reason;
        return Mono.defer(() -> {
                    var updateSpec = db.sql("UPDATE self_silence "
                                    + "SET started_at = now(), expires_at = :exp, cleared_at = NULL, "
                                    + "reason = :reason, updated_at = now() "
                                    + "WHERE user_id = :uid" + DomainScope.andPredicate(domain))
                            .bind("uid", userId)
                            .bind("exp", exp)
                            .bind("reason", safeReason);
                    return DomainScope.bind(updateSpec, domain).fetch().rowsUpdated()
                            .flatMap(updated -> updated > 0 ? Mono.empty() :
                                    db.sql("INSERT INTO self_silence "
                                                    + "(user_id, started_at, expires_at, cleared_at, reason, domain, updated_at) "
                                                    + "VALUES (:uid, now(), :exp, NULL, :reason, :dom, now())")
                                            .bind("uid", userId)
                                            .bind("exp", exp)
                                            .bind("reason", safeReason)
                                            .bind("dom", dom)
                                            .fetch().rowsUpdated().then());
                })
                // A concurrent peer won the INSERT for this same single-row PK — retry the
                // whole upsert; the retry's UPDATE-first path now finds the row.
                .retryWhen(Retry.max(UPSERT_MAX_RETRIES)
                        .filter(t -> t instanceof DuplicateKeyException))
                .then(find(userId, domain));
    }

    /**
     * Clear (stamp {@code cleared_at}) the owner's ACTIVE silence within their domain.
     * Owner+domain scoped and only-if-active ({@code cleared_at IS NULL}) so a
     * double-cancel / expiry race is idempotent. Returns the number of rows cleared
     * (0 = nothing active). {@code domain} null = SUPERADMIN cross-domain bypass.
     */
    public Mono<Long> clear(String userId, String domain) {
        var spec = db.sql("UPDATE self_silence SET cleared_at = now(), updated_at = now() "
                        + "WHERE user_id = :uid AND cleared_at IS NULL" + DomainScope.andPredicate(domain))
                .bind("uid", userId);
        return DomainScope.bind(spec, domain).fetch().rowsUpdated();
    }

    /**
     * SYSTEM clear (the scheduled expiry sweep): stamp {@code cleared_at} on the
     * user's active silence REGARDLESS of brand. The sweep is a platform task, not a
     * per-principal mutation — it processes every overdue silence found by
     * {@link #findOverdueActive(Instant)}, so it is deliberately NOT domain-scoped.
     */
    public Mono<Long> clearSystem(String userId) {
        return db.sql("UPDATE self_silence SET cleared_at = now(), updated_at = now() "
                        + "WHERE user_id = :uid AND cleared_at IS NULL")
                .bind("uid", userId).fetch().rowsUpdated();
    }

    /**
     * Active silences whose {@code expires_at} is at/before {@code asOf} — the
     * scheduled wake's work list. Re-selected on every tick (and on boot) so a
     * restart never loses a pending wake. Bounded by the partial active index.
     */
    public Flux<SelfSilence> findOverdueActive(Instant asOf) {
        return db.sql("SELECT user_id, started_at, expires_at, cleared_at, reason, updated_at "
                        + "FROM self_silence WHERE cleared_at IS NULL AND expires_at <= :asOf "
                        + "ORDER BY expires_at")
                .bind("asOf", LocalDateTime.ofInstant(asOf, ZoneOffset.UTC))
                .map(SelfSilenceRepository::map).all();
    }
}
