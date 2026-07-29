package systems.hugmesh.userbff.meshdevice;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.time.Instant;
import java.util.Set;

/**
 * One CLAIMED Meshtastic LoRa radio node belonging to the caller (table
 * {@code mesh_device}). This is the wire shape returned to the client: the saved
 * {@code id}, the CANONICAL {@code nodeId}, the optional user {@code label}, the
 * owner-managed {@code visibility}, the moderation {@code state} (+ the user-facing
 * revocation context), the bridge-reported LoRa status fields, and {@code createdAt}.
 *
 * <p>{@code nodeId} is ALWAYS the canonical form {@code "!" + exactly 8 lowercase hex
 * digits} (e.g. {@code !a1b2c3d4}) — {@link MeshDeviceService} normalizes whatever
 * accepted shape the client sent ({@code A1B2C3D4} / {@code !A1B2C3D4}) BEFORE storage,
 * and the 019 {@code ck_mesh_device_node_id} CHECK is the DB backstop. A node id is
 * GLOBALLY unique across the platform (one owner per radio — the 019
 * {@code uq_mesh_device_node_id} constraint), so the mesh↔Matrix bridge can attribute a
 * radio's messages to exactly one platform user.
 *
 * <p>{@code visibility} vocabulary (DB-paralleled by the 019 CHECK): {@code private}
 * (the default — only the owner sees the device's LoRa status) | {@code friends} |
 * {@code channels}. Owner-changed via {@code PUT /mesh-devices/{id}/visibility}.
 *
 * <p>{@code state} vocabulary (DB-paralleled by the 019 CHECK): {@code active} |
 * {@code revoked} (a moderator pulled the device, through mod-bff → the SERVICE-gated
 * {@code /bff/user/internal/mesh-devices/{id}/revoke}). A REVOKED row still shows in the
 * owner's list — with {@code state}, {@code revokeReason} and {@code revokedAt} so the
 * user sees why — but is EXCLUDED from the internal bridge mapping and its visibility
 * can no longer be changed. {@code revoked_by} (the moderator identity) is deliberately
 * NOT on this wire shape — the acting moderator is never exposed to the end user.
 *
 * <p>The LoRa status fields ({@code lastSeenAt}, {@code batteryPct} — 0..101, 101 =
 * externally powered per Meshtastic convention, {@code snr}, {@code hopsAway},
 * {@code viaDevice}) are written ONLY by the bridge through the SERVICE-gated batch
 * status endpoint; all are {@code null} until the bridge first reports the radio.
 *
 * <p>This record deliberately OMITS {@code owner_subject} and {@code domain}: the owner
 * is ALWAYS the caller themselves (owner = JWT subject, set by the controller — never a
 * request field, never echoed back), and the brand-domain is a server-side scoping
 * concern. The bridge-facing mapping (node id → Matrix localpart) is a SEPARATE,
 * SERVICE-only shape served by {@link InternalMeshDeviceController} — a USER caller can
 * never read another owner's identity off this surface.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record MeshDevice(
        String id,
        String nodeId,
        String label,
        String visibility,
        String state,
        String revokeReason,
        Instant revokedAt,
        Instant lastSeenAt,
        Integer batteryPct,
        Double snr,
        Integer hopsAway,
        String viaDevice,
        Instant createdAt) {

    /** The {@code mesh_device.visibility} vocabulary — mirrors the 019 CHECK
     *  (lock-step with {@code ValidationPatterns.MESH_VISIBILITY}). */
    public static final Set<String> VISIBILITIES = Set.of("private", "friends", "channels");

    /** {@code mesh_device.state} lifecycle literals — mirror the 019 CHECK. A fresh
     *  claim is {@code active} (the 019 column DEFAULT); {@code revoked} is written by a
     *  moderator through the SERVICE-gated internal moderation surface (mod-bff is the
     *  caller — see {@link InternalMeshDeviceController}). */
    public static final String STATE_ACTIVE = "active";
    public static final String STATE_REVOKED = "revoked";

    /** The {@code mesh_device.state} vocabulary — mirrors the 019 CHECK; the moderation
     *  list's {@code ?state=} filter validates against it. */
    public static final Set<String> STATES = Set.of(STATE_ACTIVE, STATE_REVOKED);

    /** Whether {@code v} is a member of the visibility vocabulary (the service-leg
     *  re-check, defence-in-depth behind the controller's {@code @Pattern}). */
    public static boolean validVisibility(String v) {
        return v != null && VISIBILITIES.contains(v);
    }

    /** Whether {@code s} is a member of the state vocabulary (the service-leg re-check
     *  behind the moderation controller's {@code @Pattern} on {@code ?state=}). */
    public static boolean validState(String s) {
        return s != null && STATES.contains(s);
    }
}
