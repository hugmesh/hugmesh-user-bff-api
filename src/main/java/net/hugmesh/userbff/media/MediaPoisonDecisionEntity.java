package net.hugmesh.userbff.media;

import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;

/**
 * Persisted shape of {@code media_poison_decision} (changelog 007 + 010 {@code
 * domain}). The {@code id} is an app-generated UUID PK; {@code media_ref} and
 * {@code backend} are nullable. Column names/types match the Liquibase changelog
 * EXACTLY.
 */
@Table("media_poison_decision")
public record MediaPoisonDecisionEntity(
        @Id
        @Column("id") String id,
        @Column("user_id") String userId,
        @Column("platform") String platform,
        @Column("media_ref") String mediaRef,
        @Column("mode") String mode,
        @Column("status") String status,
        @Column("backend") String backend,
        @Column("domain") String domain,
        @Column("created_at") Instant createdAt) {
}
