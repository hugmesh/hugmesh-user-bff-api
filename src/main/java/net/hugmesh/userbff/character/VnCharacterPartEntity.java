package net.hugmesh.userbff.character;

import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;

/**
 * Persisted shape of {@code vn_character_part} (changelog 016 + 018). The {@code id} is a
 * DB-generated UUID PK ((gen_random_uuid())::text — the INSERT omits it, RETURNING id
 * reads it back); {@code name} and {@code headArchetype} are nullable. {@code findingId}
 * (changelog 018, a NULLABLE bigint) is the federation {@code @system} finding id this
 * row filed — stamped best-effort AFTER the insert so a later moderator resolution of
 * that finding can flip this row's {@code status}. Column names/types match the Liquibase
 * changelog EXACTLY.
 */
@Table("vn_character_part")
public record VnCharacterPartEntity(
        @Id
        @Column("id") String id,
        @Column("owner_subject") String ownerSubject,
        @Column("domain") String domain,
        @Column("name") String name,
        @Column("svg") String svg,
        @Column("status") String status,
        @Column("head_archetype") String headArchetype,
        @Column("finding_id") Long findingId,
        @Column("created_at") Instant createdAt) {
}
