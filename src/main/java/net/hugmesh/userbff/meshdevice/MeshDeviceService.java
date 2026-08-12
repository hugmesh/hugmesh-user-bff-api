package net.hugmesh.userbff.meshdevice;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.commons.web.ApiException;
import net.hugmesh.userbff.web.ValidationPatterns;

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
 * <p>The three MODERATION methods at the bottom ({@link #listForModeration},
 * {@link #revoke}, {@link #restore}) are likewise ownerless — a moderator acts ACROSS
 * owners — and are reachable only from the {@code ROLE_SERVICE}-gated internal surface
 * ({@link InternalMeshDeviceController}), with the caller's brand as their only scope.
 *
 * <h4>Revocation semantics</h4>
 *
 * <p>A REVOKED row keeps occupying the globally-unique {@code node_id}, so a re-claim of
 * a pulled radio — by its owner under a new row, or by anyone else — hits the SAME
 * unique constraint and 409s: revocation is NOT circumventable by re-claiming while the
 * row exists. A revoked row is excluded from the bridge mapping at the SQL layer and its
 * visibility is frozen; it stays visible in the owner's own list (with the reason).
 *
 * <p><b>Documented trade-off, unchanged by the moderation wave:</b> the owner MAY delete
 * a revoked row ({@link #release} is deliberately not state-gated), which FREES the node
 * id for a fresh claim. Keep-blocked-after-delete semantics would need a separate
 * tombstone (or a soft-delete flag) that the 019 schema does not carry, so it is
 * deliberately NOT bolted on here: the moderation wave adds the WRITER for the state the
 * schema already models, it does not change the state model. mod-bff's {@code mod_action}
 * ledger keeps the durable record of every revoke/restore either way.
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

    /** {@code revoke_reason} column width (019). UNLIKE {@code via_device} this is
     *  moderator INPUT shown to the owner, so an over-long value is REJECTED (400) rather
     *  than silently truncated into a half-sentence the user has to live with. */
    static final int REVOKE_REASON_MAX = 255;

    /** {@code revoked_by} column width (019) — the acting moderator's identity. */
    static final int MODERATOR_MAX = 255;

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

    // ── Moderation (SERVICE-gated: no owner — a moderator acts across owners) ──

    /**
     * The MODERATOR console list: mesh-device rows across EVERY owner, newest claim
     * first, BOUNDED. Unlike every owner-facing method above there is NO owner argument —
     * that is the whole point of a moderation view — so the ONLY authorisation leg is the
     * {@code ROLE_SERVICE} gate on the calling surface plus the brand scope below.
     *
     * @param state  {@code active}|{@code revoked} to filter, or {@code null} for both;
     *               a value outside the {@code mesh_device.state} vocabulary is a 400
     *               (never a silently-empty list that reads as "no devices")
     * @param domain the moderator's brand, or {@code null} for the cross-domain
     *               (SUPERADMIN) view — mod-bff resolves which from the VALIDATED
     *               {@code DOMAIN_<x>} authority, never a user-settable claim
     * @param limit  caller-influenced page size; {@code null} takes the default and any
     *               value is clamped to {@link MeshDeviceRepository#MAX_MODERATION_LIMIT}
     */
    public Flux<MeshDeviceEntity> listForModeration(String state, String domain, Integer limit) {
        if (state != null && !MeshDevice.validState(state)) {
            return Flux.error(ApiException.badRequest("state must be active|revoked"));
        }
        int requested = limit == null ? MeshDeviceRepository.DEFAULT_MODERATION_LIMIT : limit;
        return repo.listForModeration(state, domain,
                MeshDeviceRepository.clampModerationLimit(requested));
    }

    /**
     * REVOKE a device (moderator action): CAS {@code active}→{@code revoked} stamping
     * {@code revoked_by}/{@code revoked_at}/{@code revoke_reason}. The write is
     * state-guarded ATOMICALLY at the SQL layer — the SAME discipline
     * {@link #setVisibility} uses — and a zero-row update is then diagnosed with a
     * brand-scoped read: an ALREADY-REVOKED row is a 409 (the house idiom for a state
     * conflict), an unknown id — or one outside the moderator's brand — is a 404 (no
     * cross-brand existence leak).
     *
     * <p>The effects the moderator is buying, all of which the schema already enforces:
     * the row leaves the bridge mapping immediately (the export is
     * {@code state='active'}-filtered), its visibility freezes (a 409 to the owner), and
     * its {@code node_id} stays occupied so the radio cannot be re-claimed by anyone
     * while the row exists.
     *
     * @param moderator the ACTING moderator's identity for the {@code revoked_by} audit
     *                  stamp — supplied by the SERVICE-principal caller (mod-bff), which
     *                  derives it from the validated moderator JWT and NEVER from its own
     *                  caller's body
     */
    public Mono<MeshDeviceEntity> revoke(String id, String domain, String moderator, String reason) {
        String mod = requireModerator(moderator);
        String why = requireReason(reason);
        return repo.revokeWhereActive(id, domain, mod, why)
                .flatMap(rows -> rows > 0
                        ? repo.findForModeration(id, domain)
                        : repo.findForModeration(id, domain)
                                .flatMap(d -> Mono.<MeshDeviceEntity>error(ApiException.conflict(
                                        "mesh device is already revoked")))
                                .switchIfEmpty(Mono.error(ApiException.notFound(
                                        "no such mesh device"))));
    }

    /**
     * RESTORE a revoked device (moderator action): CAS {@code revoked}→{@code active},
     * CLEARING the {@code revoked_by}/{@code revoked_at}/{@code revoke_reason} trio so the
     * owner stops seeing a stale reason on a device that is live again (the durable "why"
     * lives in mod-bff's {@code mod_action} ledger — this table only carries the CURRENT
     * state). Same CAS-then-diagnose discipline as {@link #revoke}: a row that is NOT
     * revoked is a 409, an unknown/out-of-brand id is a 404.
     *
     * <p>{@code moderator} is validated (and logged) but NOT persisted: the row's
     * moderation trio is cleared by the restore, so there is nowhere honest to keep it —
     * mod-bff writes the {@code mesh-device.restore} ledger row that records who did it.
     */
    public Mono<MeshDeviceEntity> restore(String id, String domain, String moderator) {
        String mod = requireModerator(moderator);
        return repo.restoreWhereRevoked(id, domain)
                .flatMap(rows -> {
                    if (rows > 0) {
                        log.info("[mesh-device] device {} RESTORED by moderator {}", id, mod);
                        return repo.findForModeration(id, domain);
                    }
                    return repo.findForModeration(id, domain)
                            .flatMap(d -> Mono.<MeshDeviceEntity>error(ApiException.conflict(
                                    "mesh device is not revoked — nothing to restore")))
                            .switchIfEmpty(Mono.error(ApiException.notFound(
                                    "no such mesh device")));
                });
    }

    /** The acting moderator's identity must be present and fit {@code revoked_by}
     *  (varchar(255), 019) — a blank/over-long value would either leave the audit stamp
     *  useless or fail at the DB, so it is a 400 here. */
    private static String requireModerator(String moderator) {
        if (moderator == null || moderator.isBlank()) {
            throw ApiException.badRequest("moderator is required");
        }
        String trimmed = moderator.trim();
        if (trimmed.length() > MODERATOR_MAX) {
            throw ApiException.badRequest("moderator must be at most " + MODERATOR_MAX + " chars");
        }
        return trimmed;
    }

    /** A revocation ALWAYS carries a reason — it is the text the OWNER is shown in their
     *  own device list, so an empty one would leave the user with a dead radio and no
     *  explanation. Capped to the {@code revoke_reason} column width (varchar(255), 019). */
    private static String requireReason(String reason) {
        if (reason == null || reason.isBlank()) {
            throw ApiException.badRequest("reason is required");
        }
        String trimmed = reason.trim();
        if (trimmed.length() > REVOKE_REASON_MAX) {
            throw ApiException.badRequest(
                    "reason must be at most " + REVOKE_REASON_MAX + " chars");
        }
        return trimmed;
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
