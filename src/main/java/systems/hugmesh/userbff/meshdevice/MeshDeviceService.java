package systems.hugmesh.userbff.meshdevice;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.hugmesh.commons.web.ApiException;
import systems.hugmesh.userbff.web.ValidationPatterns;

import java.time.Instant;
import java.util.Locale;
import java.util.regex.Pattern;

/**
 * Owner-enforced Meshtastic mesh-device operations. EVERY owner-facing method takes the
 * owner (the JWT subject, from the validated token) and operates ONLY on that owner's
 * devices:
 *
 * <ul>
 *   <li>{@link #claim} normalizes the node id to the canonical {@code "!"+lowercase-hex}
 *       form, inserts the row (owner + server-derived domain stamped), and maps the
 *       duplicate-key violation of the GLOBAL {@code uq_mesh_device_node_id} constraint
 *       to a 409 — one owner per radio, across ALL owners and domains;</li>
 *   <li>{@link #listMine} returns only the owner's own devices (REVOKED rows included,
 *       so the user sees the state + reason);</li>
 *   <li>{@link #setVisibility} changes who may see the device's LoRa status — ACTIVE
 *       rows only (a REVOKED row is a 409; unknown/foreign id a 404, no existence
 *       leak);</li>
 *   <li>{@link #release} deletes only the owner's device (scoped by owner AND id AND
 *       domain);</li>
 *   <li>{@link #applyStatus} is the SERVICE-only bridge leg (no owner — the bridge acts
 *       platform-wide, keyed by node id): fail-soft, ACTIVE-guarded, value-clamped.</li>
 * </ul>
 *
 * <h4>Revocation semantics (schema shipped here; the mod-bff writer is a LATER wave)</h4>
 *
 * <p>A REVOKED row keeps occupying the globally-unique {@code node_id}, so a re-claim of
 * a pulled radio — by its owner under a new row, or by anyone else — hits the SAME
 * unique constraint and 409s: revocation is NOT circumventable by re-claiming while the
 * row exists. A revoked row is excluded from the bridge mapping at the SQL layer and its
 * visibility is frozen; it stays visible in the owner's own list (with the reason).
 *
 * <p><b>Documented trade-off for the moderation wave to revisit:</b> the owner MAY
 * delete a revoked row ({@link #release} is deliberately not state-gated), which FREES
 * the node id for a fresh claim. Keep-blocked-after-delete semantics would need a
 * separate tombstone (or a soft-delete flag) that this schema wave does not carry —
 * revisit when mod-bff's revocation writer lands.
 */
@Service
public class MeshDeviceService {

    private static final Logger log = LoggerFactory.getLogger(MeshDeviceService.class);

    /** The accept-then-normalize claim shape (compiled once) — same source of truth as
     *  the controller's {@code @Pattern} (lock-step via {@link ValidationPatterns}). */
    private static final Pattern NODE_ID_SHAPE = Pattern.compile(ValidationPatterns.MESH_NODE_ID);

    /** Meshtastic battery telemetry range: 0..100 = percentage, 101 = externally
     *  powered (the Meshtastic convention) — mirrors the 019 CHECK. */
    private static final int BATTERY_MIN = 0;
    private static final int BATTERY_MAX = 101;

    /** {@code via_device} column width (019) — bridge-supplied text is truncated, never
     *  rejected (a status report is telemetry, not user input worth failing on). */
    private static final int VIA_DEVICE_MAX = 64;

    private final MeshDeviceRepository repo;
    /** The per-domain claim gate (capability {@code user-mesh-devices}) — dark by
     *  default; see {@link MeshClaimCapabilityGate}. Claims ONLY: the gate never
     *  touches release/visibility/status on rows that already exist. */
    private final MeshClaimCapabilityGate claimGate;

    public MeshDeviceService(MeshDeviceRepository repo, MeshClaimCapabilityGate claimGate) {
        this.repo = repo;
        this.claimGate = claimGate;
    }

    /**
     * Claim a Meshtastic radio node id under the owner. The node id is NORMALIZED first
     * (accepts {@code a1b2c3d4} / {@code !A1B2C3D4}; stores {@code !a1b2c3d4}) — the
     * controller's {@code @Pattern} is the API leg, the shape re-check here is the
     * service leg (defence-in-depth), and the 019 CHECK is the DB backstop. A node id
     * already registered — by ANYONE, in ANY domain, ACTIVE or REVOKED — violates the
     * global unique constraint and is mapped to a 409 (never a raw R2DBC error). The
     * 409 message deliberately does not say WHO holds the id.
     */
    public Mono<MeshDevice> claim(String owner, String domain, String nodeId, String label) {
        requireOwner(owner);
        String canonical = canonicalNodeId(nodeId);
        String lbl = (label == null || label.isBlank()) ? null : label.trim();
        // Per-domain capability preflight (dark by default; 403 when the domain
        // hasn't been granted+enabled 'user-mesh-devices' — see MeshClaimCapabilityGate).
        return claimGate.requireClaimAllowed(domain)
                .then(repo.save(owner, domain, canonical, lbl))
                .onErrorMap(DuplicateKeyException.class, e -> ApiException.conflict(
                        "mesh node id " + canonical + " is already registered on this platform"));
    }

    /** All of the owner's devices in their domain, newest first (own data only —
     *  REVOKED rows included so the owner sees the state + revoke reason). */
    public Flux<MeshDevice> listMine(String owner, String domain) {
        requireOwner(owner);
        return repo.listForOwner(owner, domain);
    }

    /**
     * Change who may see the device's LoRa status ({@code private|friends|channels}).
     * The write is ACTIVE-guarded + owner-scoped ATOMICALLY at the SQL layer; a zero-row
     * update is then diagnosed with an owner-scoped read: a REVOKED row of the caller's
     * is a 409 (visibility is frozen under revocation), anything else — unknown id OR
     * another owner's device — is a 404 (no cross-owner existence leak).
     */
    public Mono<MeshDevice> setVisibility(String owner, String id, String domain, String visibility) {
        requireOwner(owner);
        if (!MeshDevice.validVisibility(visibility)) {
            return Mono.error(ApiException.badRequest("visibility must be private|friends|channels"));
        }
        return repo.setVisibilityWhereActive(id, owner, visibility)
                .flatMap(rows -> rows > 0
                        ? repo.findOwned(id, owner)
                        : repo.findOwned(id, owner)
                                .flatMap(d -> Mono.<MeshDevice>error(ApiException.conflict(
                                        "mesh device is revoked — visibility cannot be changed")))
                                .switchIfEmpty(Mono.error(ApiException.notFound(
                                        "no such mesh device for this user"))));
    }

    /** Release (delete) one of the owner's devices. Deliberately NOT state-gated: a
     *  REVOKED row may be released too, which frees the node id — see the class doc for
     *  the trade-off flagged for the moderation wave. 404 when the id is unknown or not
     *  the caller's (no existence leak). */
    public Mono<Void> release(String owner, String id, String domain) {
        requireOwner(owner);
        return repo.delete(id, owner, domain).flatMap(deleted -> deleted > 0
                ? Mono.empty()
                : Mono.error(ApiException.notFound("no such mesh device for this user")));
    }

    /**
     * Apply ONE bridge status report (the SERVICE-gated batch endpoint calls this per
     * element). FAIL-SOFT end to end — telemetry must never fail the batch:
     *
     * <ul>
     *   <li>a malformed node id → the row is IGNORED (logged at debug, {@code false});</li>
     *   <li>an unknown node id, or a REVOKED row → ZERO rows updated at the SQL layer
     *       (the ACTIVE guard) → IGNORED ({@code false});</li>
     *   <li>{@code lastSeenAt} defaults to {@code now()} when the bridge sent none (a
     *       report IS a sighting);</li>
     *   <li>out-of-range values are CLAMPED, not dropped ({@code batteryPct} into
     *       0..101, {@code hopsAway} floored at 0, {@code viaDevice} truncated to the
     *       column width) — the freshest signal beats losing the whole report; the 019
     *       battery CHECK stays the DB backstop.</li>
     * </ul>
     *
     * @return {@code true} when an ACTIVE row was updated, {@code false} when the report
     *         was ignored (the batch endpoint's {@code updated}/{@code ignored} counts).
     */
    public Mono<Boolean> applyStatus(String rawNodeId, Instant lastSeenAt, Integer batteryPct,
                                     Double snr, Integer hopsAway, String viaDevice) {
        if (rawNodeId == null || !NODE_ID_SHAPE.matcher(rawNodeId.trim()).matches()) {
            log.debug("[mesh-device] bridge status report with malformed node id ignored");
            return Mono.just(false);
        }
        String canonical = canonicalizeShapeChecked(rawNodeId.trim());
        Instant seen = lastSeenAt == null ? Instant.now() : lastSeenAt;
        Integer battery = batteryPct == null ? null
                : Math.max(BATTERY_MIN, Math.min(BATTERY_MAX, batteryPct));
        Integer hops = hopsAway == null ? null : Math.max(0, hopsAway);
        String via = (viaDevice == null || viaDevice.isBlank()) ? null
                : viaDevice.trim().length() > VIA_DEVICE_MAX
                        ? viaDevice.trim().substring(0, VIA_DEVICE_MAX)
                        : viaDevice.trim();
        return repo.applyStatusWhereActive(canonical, seen, battery, snr, hops, via)
                .map(rows -> rows > 0);
    }

    /**
     * Canonicalize a CLAIMED node id: strip the optional {@code !}, lowercase, re-prefix
     * {@code !}. The service-leg shape re-check (defence-in-depth behind the
     * controller's {@code @Pattern}) throws a 400 on anything that is not 8 hex digits
     * with an optional {@code !} prefix.
     */
    static String canonicalNodeId(String raw) {
        if (raw == null || !NODE_ID_SHAPE.matcher(raw.trim()).matches()) {
            throw ApiException.badRequest(
                    "nodeId must be exactly 8 hex digits with an optional '!' prefix");
        }
        return canonicalizeShapeChecked(raw.trim());
    }

    /** The normalization itself — callers have ALREADY shape-checked {@code raw}. */
    private static String canonicalizeShapeChecked(String raw) {
        String hex = raw.startsWith("!") ? raw.substring(1) : raw;
        return "!" + hex.toLowerCase(Locale.ROOT);
    }

    private static void requireOwner(String owner) {
        if (owner == null || owner.isBlank()) {
            throw ApiException.unauthorized("missing authenticated subject");
        }
    }
}
