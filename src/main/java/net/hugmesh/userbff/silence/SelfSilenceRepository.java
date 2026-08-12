package net.hugmesh.userbff.silence;

import org.springframework.dao.DuplicateKeyException;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.util.retry.Retry;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.commons.tenancy.DomainScope;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;

/**
 * Owner-AND-domain-scoped facade over {@link SelfSilenceR2dbcRepository} for
 * {@code self_silence}. Keeps the original method surface ({@code find} / {@code
 * activate} / {@code clear} / {@code clearSystem} / {@code findOverdueActive}, with the
 * {@code default}-domain back-compat overloads + the bounded duplicate-key retry on
 * activate) so the silence service + scheduler + slice tests are unchanged; all data
 * access now flows through the reactive repository interface (no raw
 * {@code DatabaseClient SQL}).
 */
@Repository
public class SelfSilenceRepository {

    private final SelfSilenceR2dbcRepository repo;

    public SelfSilenceRepository(SelfSilenceR2dbcRepository repo) {
        this.repo = repo;
    }

    private static Instant toInstant(LocalDateTime ldt) {
        return ldt == null ? null : ldt.toInstant(ZoneOffset.UTC);
    }

    private static SelfSilence toWire(SelfSilenceEntity e) {
        return new SelfSilence(
                e.userId(), toInstant(e.startedAt()), toInstant(e.expiresAt()),
                toInstant(e.clearedAt()), e.reason(), toInstant(e.updatedAt()));
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
        var found = DomainScope.isUnscoped(domain)
                ? repo.findByUserId(userId)
                : repo.findByUserIdAndDomain(userId, domain);
        return found.map(SelfSilenceRepository::toWire);
    }

    /** Bound on the upsert's lose-the-INSERT-race retries (see {@link #activate}). */
    private static final long UPSERT_MAX_RETRIES = 8;

    /**
     * Activate (or re-activate) the owner's silence in their domain: upsert a row with
     * the given window/reason and a NULL {@code cleared_at}. ATOMIC/IDEMPOTENT and
     * PORTABLE (Postgres + H2): UPDATE-first (owner AND domain scoped), INSERT only if
     * absent (the domain is stamped server-side), the whole upsert wrapped in a bounded
     * {@code retryWhen(DuplicateKeyException)} to close the concurrent-first-INSERT
     * window for the single-row PK. Returns the freshly-written row.
     */
    public Mono<SelfSilence> activate(String userId, Instant expiresAt, String reason, String domain) {
        String dom = DomainScope.isUnscoped(domain) ? DomainRegistry.DEFAULT_DOMAIN : domain;
        LocalDateTime exp = LocalDateTime.ofInstant(expiresAt, ZoneOffset.UTC);
        String safeReason = reason == null ? "" : reason;
        return Mono.defer(() -> {
                    Mono<Long> update = DomainScope.isUnscoped(domain)
                            ? repo.activateUpdateUnscoped(userId, exp, safeReason)
                            : repo.activateUpdateScoped(userId, domain, exp, safeReason);
                    return update.flatMap(updated -> updated > 0 ? Mono.<Void>empty()
                            : repo.insertRow(userId, exp, safeReason, dom).then());
                })
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
        return DomainScope.isUnscoped(domain)
                ? repo.clearUnscoped(userId)
                : repo.clearScoped(userId, domain);
    }

    /**
     * SYSTEM clear (the scheduled expiry sweep): stamp {@code cleared_at} on the user's
     * active silence REGARDLESS of brand. The sweep is a platform task, not a
     * per-principal mutation, so it is deliberately NOT domain-scoped — identical SQL to
     * the unscoped {@link #clear}.
     */
    public Mono<Long> clearSystem(String userId) {
        return repo.clearUnscoped(userId);
    }

    /**
     * Active silences whose {@code expires_at} is at/before {@code asOf} — the
     * scheduled wake's work list. Re-selected on every tick (and on boot) so a restart
     * never loses a pending wake.
     */
    public Flux<SelfSilence> findOverdueActive(Instant asOf) {
        LocalDateTime cutoff = LocalDateTime.ofInstant(asOf, ZoneOffset.UTC);
        return repo.findByClearedAtIsNullAndExpiresAtLessThanEqualOrderByExpiresAtAsc(cutoff)
                .map(SelfSilenceRepository::toWire);
    }
}
