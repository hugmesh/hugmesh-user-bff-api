package net.hugmesh.userbff.notification;

import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;

/**
 * Persisted shape of {@code user_notifications} — the always-on in-app FLOOR inbox
 * (changelog 012). The {@code id} is an app/derived-deterministic PK. Column
 * names/types match the Liquibase changelog EXACTLY ({@code body} is a nullable clob).
 */
@Table("user_notifications")
public record UserNotificationEntity(
        @Id
        @Column("id") String id,
        @Column("domain") String domain,
        @Column("user_subject") String userSubject,
        @Column("category") String category,
        @Column("title") String title,
        @Column("body") String body,
        @Column("created_at") Instant createdAt,
        @Column("read_at") Instant readAt) {
}
