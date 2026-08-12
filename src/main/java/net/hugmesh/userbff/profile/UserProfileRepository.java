package net.hugmesh.userbff.profile;

import org.springframework.stereotype.Repository;
import reactor.core.publisher.Mono;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.commons.tenancy.DomainScope;

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
                e.visibility(), e.vanitySubdomainEnabled(), e.vanityUsername(),
                e.screenReaderName(), e.avatarUrl());
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

    /**
     * Set ONLY the owner's {@code avatar_url} (the profile picture mxc:// URL) in
     * their domain — never touching the other profile columns, so a picture change
     * can't disturb (or be disturbed by) a profile edit. UPDATE-first / INSERT-if-
     * absent, mirroring {@link #save(UserProfile, String)}: the UPDATE targets the
     * existing row (owner AND domain scoped); if no row was updated the avatar was set
     * before any profile existed, so a MINIMAL owner row is inserted (all text "" via
     * {@code nz()}, default visibility, vanity OFF, no avatar yet) and the avatar
     * UPDATE is retried against it.
     *
     * <p>Owner is always the caller's JWT subject (set by the service) and the domain
     * predicate pins the brand, so this can never write another user's / brand's row.
     * The main profile upsert deliberately does NOT carry {@code avatar_url}, so a
     * later profile save will never clear the picture this method set.
     *
     * @return the number of rows the (final) avatar UPDATE matched (1 in practice).
     */
    public Mono<Long> updateAvatarUrl(String userId, String avatarUrl, String domain) {
        Mono<Long> update = updateAvatarOnce(userId, avatarUrl, domain);
        return update.flatMap(updated -> updated > 0
                ? Mono.just(updated)
                : insertMinimalRow(userId, domain)
                        .then(updateAvatarOnce(userId, avatarUrl, domain)));
    }

    /** The avatar-only UPDATE leg, scoped or unscoped from a nullable {@code domain}. */
    private Mono<Long> updateAvatarOnce(String userId, String avatarUrl, String domain) {
        return DomainScope.isUnscoped(domain)
                ? repo.updateAvatarUrlUnscoped(userId, avatarUrl)
                : repo.updateAvatarUrlScoped(userId, domain, avatarUrl);
    }

    /** Create a MINIMAL owner row (no avatar_url yet — the caller updates it next) so
     *  an avatar set before any profile exists has a row to land on. */
    private Mono<Long> insertMinimalRow(String userId, String domain) {
        String dom = DomainScope.isUnscoped(domain) ? DomainRegistry.DEFAULT_DOMAIN : domain;
        return repo.insertRow(userId, nz(null), nz(null), nz(null), nz(null),
                UserProfile.DEFAULT_VISIBILITY, false, null, nz(null), dom);
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
