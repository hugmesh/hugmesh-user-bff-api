package systems.snapdragon.userbff.client;

import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;

/**
 * Persisted shape of {@code connected_client_audit} (changelog 009 + 010 {@code
 * domain}). The {@code id} is an app-generated UUID PK. Column names/types match the
 * Liquibase changelog EXACTLY.
 */
@Table("connected_client_audit")
public record ConnectedClientAuditEntity(
        @Id
        @Column("id") String id,
        @Column("owner") String owner,
        @Column("platform") String platform,
        @Column("client_kind") String clientKind,
        @Column("external_ref") String externalRef,
        @Column("label") String label,
        @Column("domain") String domain,
        @Column("created_at") Instant createdAt,
        @Column("revoked_at") Instant revokedAt) {
}
