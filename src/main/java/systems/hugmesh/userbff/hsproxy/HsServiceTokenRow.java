package systems.hugmesh.userbff.hsproxy;

import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.PersistenceCreator;
import org.springframework.data.annotation.Transient;
import org.springframework.data.domain.Persistable;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;
import systems.hugmesh.userbff.web.PlatformKind;

import java.time.Instant;

/**
 * One row of {@code hs_service_token} (Liquibase changeset 013) — the SERVER-SIDE
 * CUSTODY of a homeserver-NATIVE Matrix/Mastodon access (and optional refresh) token,
 * minted + held by this BFF on behalf of an authenticated subject.
 *
 * <p>SECURITY: {@code ownerSubject} is the authenticated JWT {@code sub} (the owner),
 * NEVER a request-body field — the cross-user isolation keystone is the owner-scoped SQL
 * predicate keyed on this column. {@code accessTokenEnc}/{@code refreshTokenEnc} hold the
 * AES-256-GCM {@code nonce||ciphertext||tag} (base64) of the homeserver-native tokens —
 * NEVER plaintext, NEVER returned to any client, NEVER in a GET/list response, NEVER
 * logged. {@code refreshTokenEnc}/{@code expiresAt} are NULL for Matrix (its access
 * tokens are effectively non-expiring → re-mint, no refresh).
 *
 * <p>App-generated {@code varchar(36)} UUID PK; implements {@link Persistable} so a
 * freshly minted row INSERTs and a re-mint of the SAME id UPDATEs (the data-access
 * standard's record-entity idiom, mirroring admin-bff {@code MfaFactorRow}). The custody
 * upsert is keyed on the {@code (owner_subject, platform)} unique constraint via the
 * repository's static-final {@code @Query} legs.
 */
@Table("hs_service_token")
public record HsServiceTokenRow(
        @Id @Column("id") String id,
        @Column("owner_subject") String ownerSubject,
        @Column("platform") String platform,
        @Column("access_token_enc") String accessTokenEnc,
        @Column("refresh_token_enc") String refreshTokenEnc,
        @Column("expires_at") Instant expiresAt,
        @Column("localpart") String localpart,
        @Column("minted_at") Instant mintedAt,
        @Transient boolean isNew) implements Persistable<String> {

    /** Matrix platform discriminator — sourced from the shared {@link PlatformKind#MATRIX}
     *  lens so the {@code matrix} literal lives in ONE place (wire/DB token byte-identical). */
    public static final String PLATFORM_MATRIX = PlatformKind.MATRIX.value();
    /** Mastodon platform discriminator — sourced from {@link PlatformKind#MASTODON}. */
    public static final String PLATFORM_MASTODON = PlatformKind.MASTODON.value();

    @PersistenceCreator
    public HsServiceTokenRow(String id, String ownerSubject, String platform,
                             String accessTokenEnc, String refreshTokenEnc, Instant expiresAt,
                             String localpart, Instant mintedAt) {
        this(id, ownerSubject, platform, accessTokenEnc, refreshTokenEnc, expiresAt,
                localpart, mintedAt, false);
    }

    @Override
    public String getId() {
        return id;
    }

    @Override
    public boolean isNew() {
        return isNew;
    }
}
