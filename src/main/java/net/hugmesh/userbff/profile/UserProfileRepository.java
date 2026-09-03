package net.hugmesh.userbff.profile;

import org.springframework.stereotype.Repository;
import reactor.core.publisher.Mono;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.commons.tenancy.DomainScope;

import java.util.UUID;

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

    /** The owner's stored avatar pixels + sniffed MIME, or EMPTY when they have no
     *  row or no stored body (pre-022 rows, and anyone who never uploaded).
     *
     *  Read through its OWN accessor rather than the profile DTO on purpose: pixels
     *  must never ride the profile JSON, so {@link UserProfile} has no such field. */
    public Mono<AvatarBody> findAvatarBody(String userId, String domain) {
        var found = DomainScope.isUnscoped(domain)
                ? repo.findByUserId(userId)
                : repo.findByUserIdAndDomain(userId, domain);
        return found.flatMap(e -> e.avatarBody() == null || e.avatarBody().length == 0
                ? Mono.empty()
                : Mono.just(new AvatarBody(e.avatarBody(), e.avatarContentType())));
    }

    /** Stored avatar pixels + the SNIFFED type recorded at save. */
    public record AvatarBody(byte[] bytes, String contentType) { }

    /**
     * Stored avatar pixels + sniffed type resolved by the 023 SERVE HANDLE, carrying
     * the row's OWNER and DOMAIN so the caller can make the cross-user access
     * decision. Deliberately NOT domain-scoped in the query: a cross-domain ref must
     * be refused by the SAME uniform 404 as an unknown one, which requires reading the
     * row first and comparing.
     *
     * @param owner  the subject the avatar belongs to (never echoed on the wire).
     * @param domain the brand the row lives in.
     */
    public record AvatarBodyForRef(byte[] bytes, String contentType, String owner, String domain) { }

    /**
     * The avatar bytes behind a 023 serve handle, or EMPTY when the handle is unknown
     * or the row has no stored pixels. Applies NO access rule — the caller
     * ({@code CharacterAvatarService}) owns that decision, and every refusal it makes
     * must look identical to this method's empty result.
     */
    public Mono<AvatarBodyForRef> findAvatarBodyByRef(String avatarRef) {
        if (avatarRef == null || avatarRef.isBlank()) {
            return Mono.empty();
        }
        return repo.findByAvatarRef(avatarRef)
                .flatMap(e -> e.avatarBody() == null || e.avatarBody().length == 0
                        ? Mono.empty()
                        : Mono.just(new AvatarBodyForRef(e.avatarBody(), e.avatarContentType(),
                                e.userId(), e.domain())));
    }

    /**
     * The owner's STABLE avatar serve handle (023), minting one on first use.
     *
     * <p>Lazy minting is what makes this work for rows that predate 023 — everyone who
     * had already uploaded a picture gets a handle the first time they ask for it,
     * with no data migration. It is also why the handle can never be rotated here:
     * {@code assignAvatarRef*} carries an {@code avatar_ref IS NULL} predicate, so a
     * row that already has one is left alone and two racing minters converge (the
     * loser's UPDATE matches 0 rows and the RE-READ below returns the winner's value).
     *
     * <p>Returns EMPTY when the owner has no profile row at all — a caller with no
     * stored picture must get a 404, not a freshly-minted handle pointing at nothing.
     *
     * @param userId the owner (the caller's JWT subject — never a client-supplied id).
     * @param domain the caller's brand ({@code null} = SUPERADMIN cross-domain bypass).
     */
    public Mono<String> ensureAvatarRef(String userId, String domain) {
        return findEntity(userId, domain).flatMap(e -> e.avatarRef() != null && !e.avatarRef().isBlank()
                ? Mono.just(e.avatarRef())
                : mintAvatarRef(userId, domain));
    }

    /** Mint a fresh handle, write it ONLY if the row still has none, then RE-READ so a
     *  racing minter's value (not ours) is what the caller is told. */
    private Mono<String> mintAvatarRef(String userId, String domain) {
        String minted = UUID.randomUUID().toString();
        Mono<Long> assign = DomainScope.isUnscoped(domain)
                ? repo.assignAvatarRefUnscoped(userId, minted)
                : repo.assignAvatarRefScoped(userId, domain, minted);
        return assign.then(findEntity(userId, domain))
                .flatMap(e -> e.avatarRef() == null || e.avatarRef().isBlank()
                        ? Mono.empty()
                        : Mono.just(e.avatarRef()));
    }

    /** The raw row for an owner, scoped or unscoped from a nullable {@code domain}. */
    private Mono<UserProfileEntity> findEntity(String userId, String domain) {
        return DomainScope.isUnscoped(domain)
                ? repo.findByUserId(userId)
                : repo.findByUserIdAndDomain(userId, domain);
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
    public Mono<Long> updateAvatarUrl(String userId, String avatarUrl, String domain,
                                      byte[] avatarBody, String avatarContentType) {
        Mono<Long> update = updateAvatarOnce(userId, avatarUrl, domain, avatarBody, avatarContentType);
        return update.flatMap(updated -> updated > 0
                ? Mono.just(updated)
                : insertMinimalRow(userId, domain)
                        .then(updateAvatarOnce(userId, avatarUrl, domain, avatarBody, avatarContentType)));
    }

    /** The avatar-only UPDATE leg, scoped or unscoped from a nullable {@code domain}. */
    private Mono<Long> updateAvatarOnce(String userId, String avatarUrl, String domain,
                                        byte[] avatarBody, String avatarContentType) {
        return DomainScope.isUnscoped(domain)
                ? repo.updateAvatarUrlUnscoped(userId, avatarUrl, avatarBody, avatarContentType)
                : repo.updateAvatarUrlScoped(userId, domain, avatarUrl, avatarBody, avatarContentType);
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
