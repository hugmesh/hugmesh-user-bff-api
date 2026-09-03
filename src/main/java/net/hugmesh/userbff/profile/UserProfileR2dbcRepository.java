package net.hugmesh.userbff.profile;

import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Mono;

/**
 * Reactive (R2DBC) store for {@code user_profile} — keyed by the owner
 * ({@code user_id} = Casdoor JWT subject) AND domain-scoped by {@code domain} (the
 * validated-issuer brand). Matches the {@code hugmesh-federation-api}
 * {@code R2dbcRepository} idiom: DERIVED finders/deletes for the read/delete paths,
 * an {@code @Query} (static-final SQL constant) only for the UPDATE-first /
 * INSERT-if-absent upsert that cannot be derived (server-side {@code now()}, partial
 * columns, portable cross-engine shape).
 *
 * <p>The optional {@code domain} predicate is split into a SCOPED finder (with
 * {@code AND domain = :domain}) and an UNSCOPED finder (no predicate) — the SUPERADMIN
 * cross-domain bypass selects the unscoped variant, MIRRORING federation's
 * {@code findBySlug} / {@code findBySlugAndDomain} pair. The thin {@code @Repository}
 * facade {@link UserProfileRepository} chooses the variant from a nullable
 * {@code domain}.
 */
public interface UserProfileR2dbcRepository extends ReactiveCrudRepository<UserProfileEntity, String> {

    // ---- READ (derived) ----

    /** The owner's profile in ALL brands (SUPERADMIN cross-domain bypass). The PK is
     *  {@code user_id}, so at most one row — Mono. */
    Mono<UserProfileEntity> findByUserId(String userId);

    /** The owner's profile pinned to one brand (the per-domain caller path). */
    Mono<UserProfileEntity> findByUserIdAndDomain(String userId, String domain);

    // ---- DELETE (derived) ----

    Mono<Long> deleteByUserId(String userId);

    Mono<Long> deleteByUserIdAndDomain(String userId, String domain);

    // ---- UPSERT (@Query — UPDATE-first then INSERT-if-absent, server-side now()) ----

    /** SCOPED upsert UPDATE leg (owner AND domain). */
    String UPDATE_SCOPED =
            "UPDATE user_profile SET gender = :gender, pronouns = :pronouns, timezone = :timezone, "
            + "display_name = :displayName, visibility = :visibility, "
            + "vanity_subdomain_enabled = :vanityEnabled, vanity_username = :vanityUsername, "
            + "screen_reader_name = :screenReaderName, updated_at = now() "
            + "WHERE user_id = :userId AND domain = :domain";

    /** UNSCOPED upsert UPDATE leg (owner only — SUPERADMIN bypass). */
    String UPDATE_UNSCOPED =
            "UPDATE user_profile SET gender = :gender, pronouns = :pronouns, timezone = :timezone, "
            + "display_name = :displayName, visibility = :visibility, "
            + "vanity_subdomain_enabled = :vanityEnabled, vanity_username = :vanityUsername, "
            + "screen_reader_name = :screenReaderName, updated_at = now() "
            + "WHERE user_id = :userId";

    String INSERT =
            "INSERT INTO user_profile (user_id, gender, pronouns, timezone, display_name, "
            + "visibility, vanity_subdomain_enabled, vanity_username, screen_reader_name, domain, updated_at) "
            + "VALUES (:userId, :gender, :pronouns, :timezone, :displayName, :visibility, "
            + ":vanityEnabled, :vanityUsername, :screenReaderName, :domain, now())";

    @Modifying
    @Query(UPDATE_SCOPED)
    Mono<Long> updateScoped(@Param("userId") String userId, @Param("domain") String domain,
                            @Param("gender") String gender, @Param("pronouns") String pronouns,
                            @Param("timezone") String timezone, @Param("displayName") String displayName,
                            @Param("visibility") String visibility,
                            @Param("vanityEnabled") boolean vanityEnabled,
                            @Param("vanityUsername") String vanityUsername,
                            @Param("screenReaderName") String screenReaderName);

    @Modifying
    @Query(UPDATE_UNSCOPED)
    Mono<Long> updateUnscoped(@Param("userId") String userId,
                              @Param("gender") String gender, @Param("pronouns") String pronouns,
                              @Param("timezone") String timezone, @Param("displayName") String displayName,
                              @Param("visibility") String visibility,
                              @Param("vanityEnabled") boolean vanityEnabled,
                              @Param("vanityUsername") String vanityUsername,
                              @Param("screenReaderName") String screenReaderName);

    @Modifying
    @Query(INSERT)
    Mono<Long> insertRow(@Param("userId") String userId, @Param("gender") String gender,
                         @Param("pronouns") String pronouns, @Param("timezone") String timezone,
                         @Param("displayName") String displayName, @Param("visibility") String visibility,
                         @Param("vanityEnabled") boolean vanityEnabled,
                         @Param("vanityUsername") String vanityUsername,
                         @Param("screenReaderName") String screenReaderName,
                         @Param("domain") String domain);

    // ---- AVATAR (@Query — avatar-only UPDATE, server-side now()) ----
    //
    // The profile picture (mxc:// URL) is written by the dedicated avatar endpoint
    // ONLY — its own UPDATE that touches avatar_url alone, so it never disturbs the
    // other profile columns and the main upsert never clears it. Scoped (owner AND
    // domain) + unscoped (owner only, SUPERADMIN bypass) variants, mirroring the
    // UPDATE_SCOPED / UPDATE_UNSCOPED pair above.

    // The avatar UPDATEs carry the BYTES with the ref (022). One statement, so a
    // stored body can never disagree with the avatar_url written beside it.

    /** SCOPED avatar UPDATE (owner AND domain). */
    String UPDATE_AVATAR_SCOPED =
            "UPDATE user_profile SET avatar_url = :avatarUrl, avatar_body = :avatarBody, "
            + "avatar_content_type = :avatarContentType, updated_at = now() "
            + "WHERE user_id = :userId AND domain = :domain";

    /** UNSCOPED avatar UPDATE (owner only — SUPERADMIN bypass). */
    String UPDATE_AVATAR_UNSCOPED =
            "UPDATE user_profile SET avatar_url = :avatarUrl, avatar_body = :avatarBody, "
            + "avatar_content_type = :avatarContentType, updated_at = now() "
            + "WHERE user_id = :userId";

    @Modifying
    @Query(UPDATE_AVATAR_SCOPED)
    Mono<Long> updateAvatarUrlScoped(@Param("userId") String userId, @Param("domain") String domain,
                                     @Param("avatarUrl") String avatarUrl,
                                     @Param("avatarBody") byte[] avatarBody,
                                     @Param("avatarContentType") String avatarContentType);

    @Modifying
    @Query(UPDATE_AVATAR_UNSCOPED)
    Mono<Long> updateAvatarUrlUnscoped(@Param("userId") String userId,
                                       @Param("avatarUrl") String avatarUrl,
                                       @Param("avatarBody") byte[] avatarBody,
                                       @Param("avatarContentType") String avatarContentType);

    // ---- AVATAR REF (023 — the cross-user serve handle) ----
    //
    // The opaque per-owner handle the avatar is served under to OTHER users
    // (GET /bff/user/character/avatar/{ref}/body). Minted ONCE and never rotated: a
    // forum VN profile stores the resulting path, so a rotating ref would silently
    // break every already-saved sprite.

    /** Reverse lookup: the profile row carrying this serve handle (UNIQUE by 023's
     *  index, so at most one). Deliberately NOT domain-scoped — the row's own
     *  {@code domain} is what the caller's domain is then compared against, and a
     *  cross-domain miss must be indistinguishable from an unknown ref (a uniform
     *  404), not a different query. */
    Mono<UserProfileEntity> findByAvatarRef(String avatarRef);

    /** MINT-IF-ABSENT (scoped): assign the handle ONLY when the row has none. The
     *  {@code avatar_ref IS NULL} predicate is what makes minting idempotent and
     *  concurrency-safe — a second racing mint matches 0 rows and the caller re-reads
     *  the winner, so one owner can never end up with two live handles. Does NOT touch
     *  {@code updated_at}: minting a serve handle is not a profile edit. */
    String ASSIGN_AVATAR_REF_SCOPED =
            "UPDATE user_profile SET avatar_ref = :avatarRef "
            + "WHERE user_id = :userId AND domain = :domain AND avatar_ref IS NULL";

    /** MINT-IF-ABSENT (unscoped — the SUPERADMIN cross-domain bypass). */
    String ASSIGN_AVATAR_REF_UNSCOPED =
            "UPDATE user_profile SET avatar_ref = :avatarRef "
            + "WHERE user_id = :userId AND avatar_ref IS NULL";

    @Modifying
    @Query(ASSIGN_AVATAR_REF_SCOPED)
    Mono<Long> assignAvatarRefScoped(@Param("userId") String userId, @Param("domain") String domain,
                                     @Param("avatarRef") String avatarRef);

    @Modifying
    @Query(ASSIGN_AVATAR_REF_UNSCOPED)
    Mono<Long> assignAvatarRefUnscoped(@Param("userId") String userId,
                                       @Param("avatarRef") String avatarRef);
}
