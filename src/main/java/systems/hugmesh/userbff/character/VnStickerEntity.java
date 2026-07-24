package systems.hugmesh.userbff.character;

import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;

/**
 * Persisted shape of {@code vn_sticker_pack} (changelog 017 + 018 + 020). The {@code id}
 * is a DB-generated UUID PK ((gen_random_uuid())::text — the INSERT omits it, RETURNING id
 * reads it back); {@code expression} and {@code mxcUrl} are NOT NULL. {@code findingId}
 * (changelog 018, a NULLABLE bigint) is the federation {@code @system} finding id this
 * row filed — stamped best-effort AFTER the insert so a later moderator resolution of
 * that finding can flip this row's {@code status}. {@code body} + {@code contentType}
 * (changelog 020, both NULLABLE) are the sticker's raw moderated image bytes and the
 * magic-byte-SNIFFED MIME type recorded at save — the BFF body-serve source
 * ({@code GET /bff/user/character/stickers/{slug}/body}); pre-020 rows have {@code null}
 * body (only the mxc:// ref) and simply do not body-serve. Column names/types match the
 * Liquibase changelog EXACTLY.
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
        @Column("created_at") Instant createdAt,
        @Column("body") byte[] body,
        @Column("content_type") String contentType) {
}
