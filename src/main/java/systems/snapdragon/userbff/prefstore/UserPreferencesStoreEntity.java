package systems.snapdragon.userbff.prefstore;

import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;

/**
 * Persisted shape of {@code user_preferences_store} — the DURABLE per-user UI
 * preferences (composite PK {@code (user_id, pref_key, domain)} from changelog 011).
 * Column names/types match the Liquibase changelog EXACTLY.
 *
 * <p>The TRUE PK is composite; Spring Data needs a single {@code @Id} for entity
 * metadata, so {@code user_id} carries it. The repo never keys CRUD-by-id — all access
 * is DERIVED finders / {@code @Query} upsert+delete — so the marker never narrows a
 * query.
 */
@Table("user_preferences_store")
public record UserPreferencesStoreEntity(
        @Id
        @Column("user_id") String userId,
        @Column("pref_key") String prefKey,
        @Column("pref_value") String prefValue,
        @Column("domain") String domain,
        @Column("updated_at") Instant updatedAt) {
}
