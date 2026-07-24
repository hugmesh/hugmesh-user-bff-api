package systems.hugmesh.userbff.meshdevice;

import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;

/**
 * Persisted shape of {@code mesh_device} (changelog 019). The {@code id} is a
 * DB-generated UUID PK ((gen_random_uuid())::text — the INSERT omits it, RETURNING id
 * reads it back, 015 idiom); {@code nodeId} is the CANONICAL {@code !}-prefixed
 * lowercase-hex Meshtastic node id (service-normalized before insert; GLOBALLY unique —
 * one owner per radio — and CHECK-constrained to the canonical shape); {@code label} is
 * nullable.
 *
 * <p>{@code visibility} ({@code private|friends|channels}, DEFAULT {@code private}) is
 * owner-managed; {@code state} ({@code active|revoked}, DEFAULT {@code active}) plus the
 * {@code revokedBy}/{@code revokedAt}/{@code revokeReason} audit trio are the moderation
 * columns (written by mod-bff in a LATER wave); the LoRa status columns
 * ({@code lastSeenAt}, {@code batteryPct} 0..101, {@code snr}, {@code hopsAway},
 * {@code viaDevice}) are written only by the bridge's SERVICE-gated batch status update
 * and stay {@code null} until first report. Column names/types match the Liquibase
 * changelog EXACTLY.
 */
@Table("mesh_device")
public record MeshDeviceEntity(
        @Id
        @Column("id") String id,
        @Column("owner_subject") String ownerSubject,
        @Column("domain") String domain,
        @Column("node_id") String nodeId,
        @Column("label") String label,
        @Column("visibility") String visibility,
        @Column("state") String state,
        @Column("revoked_by") String revokedBy,
        @Column("revoked_at") Instant revokedAt,
        @Column("revoke_reason") String revokeReason,
        @Column("last_seen_at") Instant lastSeenAt,
        @Column("battery_pct") Integer batteryPct,
        @Column("snr") Double snr,
        @Column("hops_away") Integer hopsAway,
        @Column("via_device") String viaDevice,
        @Column("created_at") Instant createdAt) {
}
