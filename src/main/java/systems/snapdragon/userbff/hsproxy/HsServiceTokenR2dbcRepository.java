package systems.snapdragon.userbff.hsproxy;

import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Mono;

/**
 * Reactive (R2DBC) Spring Data store for {@code hs_service_token} (changeset 013). All
 * reads/writes are SCOPED to the owner — the proxy load, the custody upsert and the
 * delete only ever touch the caller's OWN custody row (the cross-user isolation
 * keystone: subject A can never read/use/refresh subject B's token because every
 * predicate is keyed on {@code owner_subject}). The upsert + delete are {@code @Query}
 * static-final constants; the lookup is a derived finder. No raw {@code DatabaseClient}
 * (the data-access standard); mirrors admin-bff {@code MfaFactorR2dbcRepository}.
 */
public interface HsServiceTokenR2dbcRepository
        extends ReactiveCrudRepository<HsServiceTokenRow, String> {

    /** The owner's custody row for a platform (the proxy load + refresh path). Owner-
     *  scoped: another subject's row is unreachable through this finder. */
    Mono<HsServiceTokenRow> findByOwnerSubjectAndPlatform(String ownerSubject, String platform);

    // ── Custody UPSERT (@Query, keyed on the (owner_subject, platform) unique constraint) ──

    /** Refresh an existing custody row IN PLACE — keyed on (owner, platform) so a caller
     *  can only ever rewrite THEIR OWN token (cross-user isolation at the SQL predicate). */
    String UPSERT_UPDATE =
            "UPDATE hs_service_token SET access_token_enc = :accessEnc, "
            + "refresh_token_enc = :refreshEnc, expires_at = :expiresAt, "
            + "localpart = :localpart, minted_at = now() "
            + "WHERE owner_subject = :ownerSubject AND platform = :platform";

    @Modifying
    @Query(UPSERT_UPDATE)
    Mono<Long> upsertUpdate(@Param("ownerSubject") String ownerSubject,
                            @Param("platform") String platform,
                            @Param("accessEnc") String accessEnc,
                            @Param("refreshEnc") String refreshEnc,
                            @Param("expiresAt") java.time.Instant expiresAt,
                            @Param("localpart") String localpart);

    /** Insert a fresh custody row (the first mint for this owner+platform). The
     *  (owner_subject, platform) unique constraint makes the update-first/insert-if-absent
     *  upsert a true upsert (no find-then-insert race window).
     *
     *  <p>DB-GENERATED id (changelog 015): the id is OMITTED so Postgres fills it from its
     *  (gen_random_uuid())::text column DEFAULT; RETURNING id reads the generated UUID
     *  string back. A plain (non-{@code @Modifying}) {@code @Query} returning
     *  {@code Mono<String>} — empty when 0 rows insert (it cannot, the update-first leg
     *  already ran), the new id on the fresh insert. */
    String UPSERT_INSERT_RETURNING_ID =
            "INSERT INTO hs_service_token "
            + "(owner_subject, platform, access_token_enc, refresh_token_enc, "
            + "expires_at, localpart, minted_at) "
            + "VALUES (:ownerSubject, :platform, :accessEnc, :refreshEnc, "
            + ":expiresAt, :localpart, now()) "
            + "RETURNING id";

    @Query(UPSERT_INSERT_RETURNING_ID)
    Mono<String> upsertInsertReturningId(@Param("ownerSubject") String ownerSubject,
                                         @Param("platform") String platform,
                                         @Param("accessEnc") String accessEnc,
                                         @Param("refreshEnc") String refreshEnc,
                                         @Param("expiresAt") java.time.Instant expiresAt,
                                         @Param("localpart") String localpart);

    /** Owner-scoped hard delete of a custody row — keyed on (owner, platform) so a caller
     *  can NEVER delete another subject's token. Returns rows-deleted (0 = not the
     *  caller's row / none). */
    String DELETE_BY_OWNER_AND_PLATFORM =
            "DELETE FROM hs_service_token "
            + "WHERE owner_subject = :ownerSubject AND platform = :platform";

    @Modifying
    @Query(DELETE_BY_OWNER_AND_PLATFORM)
    Mono<Long> deleteByOwnerSubjectAndPlatform(@Param("ownerSubject") String ownerSubject,
                                               @Param("platform") String platform);
}
