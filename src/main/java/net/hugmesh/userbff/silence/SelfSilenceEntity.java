package net.hugmesh.userbff.silence;

import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.LocalDateTime;

/**
 * Persisted shape of {@code self_silence} (changelog 006 + 010 {@code domain}). PK is
 * {@code user_id} (one row per user). Timestamps are mapped as {@code LocalDateTime}
 * (the {@code timestamp} columns the original repo read/wrote in UTC via
 * {@code LocalDateTime.ofInstant(..., UTC)}); the facade converts to/from
 * {@code Instant} so the {@link SelfSilence} wire record is unchanged. Column
 * names/types match the Liquibase changelog EXACTLY.
 */
@Table("self_silence")
public record SelfSilenceEntity(
        @Id
        @Column("user_id") String userId,
        @Column("started_at") LocalDateTime startedAt,
        @Column("expires_at") LocalDateTime expiresAt,
        @Column("cleared_at") LocalDateTime clearedAt,
        @Column("reason") String reason,
        @Column("domain") String domain,
        @Column("updated_at") LocalDateTime updatedAt) {
}
