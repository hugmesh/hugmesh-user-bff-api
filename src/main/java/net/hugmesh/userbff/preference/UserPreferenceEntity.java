package net.hugmesh.userbff.preference;

import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;

/**
 * Persisted shape of {@code user_preference} — the legacy home-guide key/value store
 * (composite PK {@code (user_id, pref_key)} from changelog 002, plus the 010 {@code
 * domain} column). Column names/types match the Liquibase changelog EXACTLY.
 *
 * <p>The TRUE PK is composite {@code (user_id, pref_key)}; Spring Data needs a single
 * {@code @Id} for entity metadata, so {@code user_id} carries it. The repo never keys
 * CRUD-by-id — all access is DERIVED finders / {@code @Query} upsert+delete — so the
 * single-{@code @Id} marker is metadata-only and never narrows a query.
 */
@Table("user_preference")
public record UserPreferenceEntity(
        @Id
        @Column("user_id") String userId,
        @Column("pref_key") String prefKey,
        @Column("pref_value") String prefValue,
        @Column("domain") String domain,
        @Column("updated_at") Instant updatedAt) {
}
