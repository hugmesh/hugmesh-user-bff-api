package systems.hugmesh.userbff.profile;

import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;

/**
 * Persisted shape of {@code user_profile} (the relational entity backing
 * {@link UserProfileRepository}). Distinct from the {@link UserProfile} WIRE record
 * (which carries Jackson/validation annotations) so the persistence mapping and the
 * API contract evolve independently. Column names/types match the Liquibase changelog
 * (001 + 004 vanity_username + 008 screen_reader_name + 010 domain + 014 avatar_url)
 * EXACTLY.
 *
 * <p>{@code userId} is the natural PK (Casdoor JWT subject); {@code @Id} marks it so
 * the reactive repository's CRUD keys on it. {@code domain} is the multi-brand tenant
 * (010, DEFAULT 'default'). Mutations go through {@code @Query} upserts in the repo
 * (UPDATE-first/INSERT-if-absent with server-side {@code now()}), so this entity is
 * the read projection + the column inventory of record.
 */
@Table("user_profile")
public record UserProfileEntity(
        @Id
        @Column("user_id") String userId,
        @Column("gender") String gender,
        @Column("pronouns") String pronouns,
        @Column("timezone") String timezone,
        @Column("display_name") String displayName,
        @Column("visibility") String visibility,
        @Column("vanity_subdomain_enabled") boolean vanitySubdomainEnabled,
        @Column("vanity_username") String vanityUsername,
        @Column("screen_reader_name") String screenReaderName,
        @Column("avatar_url") String avatarUrl,
        @Column("domain") String domain,
        @Column("updated_at") Instant updatedAt) {
}
