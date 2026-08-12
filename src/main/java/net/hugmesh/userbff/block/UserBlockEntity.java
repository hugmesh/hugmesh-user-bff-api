package net.hugmesh.userbff.block;

import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;

/**
 * Persisted shape of {@code user_block} (changelog 003 + 010 {@code domain}). The
 * {@code id} is an app-generated UUID PK. Column names/types match the Liquibase
 * changelog EXACTLY.
 */
@Table("user_block")
public record UserBlockEntity(
        @Id
        @Column("id") String id,
        @Column("user_id") String userId,
        @Column("target") String target,
        @Column("platform") String platform,
        @Column("domain") String domain,
        @Column("ts") Instant ts) {
}
