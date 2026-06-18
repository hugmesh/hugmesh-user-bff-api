package systems.snapdragon.userbff.profile;

import org.springframework.stereotype.Repository;
import reactor.core.publisher.Mono;
import systems.snapdragon.userbff.security.DomainRegistry;
import systems.snapdragon.userbff.security.DomainScope;

/**
 * Owner-AND-domain-scoped facade over the Spring Data {@link UserProfileR2dbcRepository}
 * for {@code user_profile}. Keeps the original method surface ({@code find} / {@code save}
 * / {@code delete}, with the {@code default}-domain back-compat overloads) so the service
 * and slice tests are unchanged, while ALL data access now flows through the reactive
 * repository interface (no raw {@code DatabaseClient SQL}).
 *
 * <p>The nullable {@code domain} selects between the SCOPED finder ({@code AND domain =
 * :domain}) and the UNSCOPED finder (no predicate, the SUPERADMIN cross-domain bypass) —
 * the data-layer half of the multi-brand isolation boundary, exactly as before.
 */
@Repository
public class UserProfileRepository {

    private final UserProfileR2dbcRepository repo;

    public UserProfileRepository(UserProfileR2dbcRepository repo) {
        this.repo = repo;
    }

    private static UserProfile toWire(UserProfileEntity e) {
        return new UserProfile(
                e.userId(), e.gender(), e.pronouns(), e.timezone(), e.displayName(),
                e.visibility(), e.vanitySubdomainEnabled(), e.vanityUsername(), e.screenReaderName());
    }

    /** Back-compat overload — scopes to the platform {@code default} domain. */
    public Mono<UserProfile> find(String userId) {
        return find(userId, DomainRegistry.DEFAULT_DOMAIN);
    }

    /** Back-compat overload — stamps/operates on the platform {@code default} domain. */
    public Mono<UserProfile> save(UserProfile p) {
        return save(p, DomainRegistry.DEFAULT_DOMAIN);
    }

    /** Back-compat overload — scopes to the platform {@code default} domain. */
    public Mono<Void> delete(String userId) {
        return delete(userId, DomainRegistry.DEFAULT_DOMAIN);
    }

    /** The owner's profile in their domain, or empty if they have never created one
     *  ({@code domain} null = SUPERADMIN cross-domain bypass). */
    public Mono<UserProfile> find(String userId, String domain) {
        var found = DomainScope.isUnscoped(domain)
                ? repo.findByUserId(userId)
                : repo.findByUserIdAndDomain(userId, domain);
        return found.map(UserProfileRepository::toWire);
    }

    /**
     * Upsert the owner's profile in their domain. Portable (Postgres + H2): UPDATE
     * first (owner AND domain scoped), then INSERT only if no row was updated (the
     * domain is stamped server-side). The owner id is always the caller's JWT subject
     * (set by the service), so this can never touch another user's row; the domain
     * predicate additionally prevents touching another brand's row.
     */
    public Mono<UserProfile> save(UserProfile p, String domain) {
        String dom = DomainScope.isUnscoped(domain) ? DomainRegistry.DEFAULT_DOMAIN : domain;
        // vanity_username is a REAL NULL when unset (so the reserved-name CHECK's IS NULL
        // branch fires); the other text columns coerce to "" exactly as the legacy nz().
        Mono<Long> update = DomainScope.isUnscoped(domain)
                ? repo.updateUnscoped(p.userId(), nz(p.gender()), nz(p.pronouns()), nz(p.timezone()),
                        nz(p.displayName()), p.visibility(), p.vanitySubdomainEnabled(),
                        p.vanityUsername(), nz(p.screenReaderName()))
                : repo.updateScoped(p.userId(), domain, nz(p.gender()), nz(p.pronouns()), nz(p.timezone()),
                        nz(p.displayName()), p.visibility(), p.vanitySubdomainEnabled(),
                        p.vanityUsername(), nz(p.screenReaderName()));
        return update.flatMap(updated -> updated > 0
                ? Mono.just(p)
                : repo.insertRow(p.userId(), nz(p.gender()), nz(p.pronouns()), nz(p.timezone()),
                            nz(p.displayName()), p.visibility(), p.vanitySubdomainEnabled(),
                            p.vanityUsername(), nz(p.screenReaderName()), dom)
                        .thenReturn(p));
    }

    /** Delete the owner's profile (own data only; owner AND domain scoped). */
    public Mono<Void> delete(String userId, String domain) {
        var deleted = DomainScope.isUnscoped(domain)
                ? repo.deleteByUserId(userId)
                : repo.deleteByUserIdAndDomain(userId, domain);
        return deleted.then();
    }

    /** Bind-safe empty-string for nullable text columns (avoids bindNull churn). */
    private static String nz(String s) {
        return s == null ? "" : s;
    }
}
