package systems.snapdragon.userbff.character;

import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;

/**
 * Persisted shape of {@code vn_sticker_pack} (changelog 017 + 018). The {@code id} is a
 * DB-generated UUID PK ((gen_random_uuid())::text — the INSERT omits it, RETURNING id
 * reads it back); {@code expression} and {@code mxcUrl} are NOT NULL. {@code findingId}
 * (changelog 018, a NULLABLE bigint) is the federation {@code @system} finding id this
 * row filed — stamped best-effort AFTER the insert so a later moderator resolution of
 * that finding can flip this row's {@code status}. Column names/types match the Liquibase
 * changelog EXACTLY.
 */
@Table("vn_sticker_pack")
public record VnStickerEntity(
        @Id
        @Column("id") String id,
        @Column("owner_subject") String ownerSubject,
        @Column("domain") String domain,
        @Column("expression") String expression,
        @Column("mxc_url") String mxcUrl,
        @Column("status") String status,
        @Column("finding_id") Long findingId,
        @Column("created_at") Instant createdAt) {
}
