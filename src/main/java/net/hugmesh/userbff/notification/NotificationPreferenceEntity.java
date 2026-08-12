package net.hugmesh.userbff.notification;

import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;

/**
 * Persisted shape of {@code notification_preference} — the per-category opt-in/out
 * (composite PK {@code (domain, user_subject, category)} from changelog 012). Column
 * names/types match the Liquibase changelog EXACTLY.
 *
 * <p>The TRUE PK is composite; Spring Data needs a single {@code @Id} for metadata, so
 * {@code user_subject} carries it. The repo never keys CRUD-by-id — all access is
 * DERIVED finders / {@code @Query} upsert — so the marker never narrows a query.
 */
@Table("notification_preference")
public record NotificationPreferenceEntity(
        @Column("domain") String domain,
        @Id
        @Column("user_subject") String userSubject,
        @Column("category") String category,
        @Column("enabled") boolean enabled,
        @Column("updated_at") Instant updatedAt) {
}
