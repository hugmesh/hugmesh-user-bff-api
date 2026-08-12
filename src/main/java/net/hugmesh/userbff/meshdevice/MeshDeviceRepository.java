package net.hugmesh.userbff.meshdevice;

import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.commons.tenancy.DomainScope;

import java.time.Instant;

/**
 * Owner-AND-domain-scoped facade over {@link MeshDeviceR2dbcRepository} for
 * {@code mesh_device}. Mirrors {@code VnCharacterPartRepository}: all data access flows
 * through the reactive repository interface (no raw SQL); the {@code save} does an
 * INSERT ... RETURNING id then a read-back to return the persisted wire shape;
 * {@code listForOwner}/{@code findOwned}/{@code delete} are owner-scoped so a caller can
 * never read or release another user's device.
 *
 * <p>A {@code null}/unscoped {@code domain} is the SUPERADMIN cross-domain bypass; an
 * unscoped SAVE stamps {@link DomainRegistry#DEFAULT_DOMAIN}.
 *
 * <p>The MODERATION members at the bottom ({@link #listForModeration},
 * {@link #findForModeration}, {@link #revokeWhereActive}, {@link #restoreWhereRevoked})
 * are the ONLY methods here that are not owner-scoped — a moderator acts across owners by
 * definition. They are reachable ONLY from the SERVICE-gated internal surface
 * ({@link InternalMeshDeviceController}), stay BRAND-scoped whenever the caller supplies a
 * domain, and both state writes are SQL-layer CAS statements (the source state is a WHERE
 * predicate) so a transition can never interleave with a concurrent one.
 */
@Repository
public class MeshDeviceRepository {

    private final MeshDeviceR2dbcRepository repo;

    public MeshDeviceRepository(MeshDeviceR2dbcRepository repo) {
        this.repo = repo;
    }

    /** Row → wire. Deliberately drops {@code owner_subject}/{@code domain} (server-side
     *  scoping concerns) AND {@code revoked_by} (the moderator identity is never exposed
     *  to the end user) — see {@link MeshDevice}. */
    private static MeshDevice toWire(MeshDeviceEntity e) {
        return new MeshDevice(
                e.id(), e.nodeId(), e.label(), e.visibility(), e.state(),
                e.revokeReason(), e.revokedAt(),
                e.lastSeenAt(), e.batteryPct(), e.snr(), e.hopsAway(), e.viaDevice(),
                e.createdAt());
    }

    /**
     * Persist a claim for the owner (app-omits id; the DB generates it) and return it.
     * {@code nodeId} is ALREADY the canonical {@code !}+lowercase-hex form (the service
     * normalizes before calling here). The owner is the JWT subject the service passes —
     * never a request field. {@code label} is nullable. A node id already present in the
     * table (ANY owner, ANY domain, ANY state — including {@code revoked}) violates the
     * 019 {@code uq_mesh_device_node_id} UNIQUE constraint and surfaces as a
     * {@code DuplicateKeyException} the service maps to a 409.
     */
    public Mono<MeshDevice> save(String ownerSubject, String domain, String nodeId, String label) {
        String dom = DomainScope.isUnscoped(domain) ? DomainRegistry.DEFAULT_DOMAIN : domain;
        // The id is DB-generated (changelog 019 column DEFAULT, 015 idiom): the INSERT
        // omits it and RETURNING id hands back the generated UUID string, which drives
        // the read-back.
        return repo.insertRowReturningId(ownerSubject, dom, nodeId, label)
                .flatMap(repo::findById)
                .map(MeshDeviceRepository::toWire);
    }

    /** All of the owner's devices in their domain (own data only), newest first —
     *  REVOKED rows included (the owner sees the state + reason); {@code domain} null =
     *  SUPERADMIN cross-domain bypass. */
    public Flux<MeshDevice> listForOwner(String ownerSubject, String domain) {
        var rows = DomainScope.isUnscoped(domain)
                ? repo.findByOwnerSubjectOrderByCreatedAtDesc(ownerSubject)
                : repo.findByOwnerSubjectAndDomainOrderByCreatedAtDesc(ownerSubject, domain);
        return rows.map(MeshDeviceRepository::toWire);
    }

    /**
     * The owner's single device by id (the visibility-change diagnose path). Owner-scoped
     * at the SQL layer so a caller can never read another user's device even with a known
     * id — a foreign id yields empty (the service maps that to a 404, never a 403, so
     * existence is not leaked). NOTE: owner-scoped (not domain-scoped) because this path
     * is keyed by the opaque UUID id the owner already holds; a device is single-owner —
     * the same rationale as {@code VnCharacterPartRepository#findOwned}.
     */
    public Mono<MeshDevice> findOwned(String id, String ownerSubject) {
        return repo.findByIdAndOwnerSubject(id, ownerSubject)
                .map(MeshDeviceRepository::toWire);
    }

    /** Release one of the owner's devices (scoped by owner AND domain AND id; domain
     *  null = SUPERADMIN unscoped). A REVOKED row may be released too (the owner frees
     *  the node id — see the service doc for the moderation trade-off). Rows deleted. */
    public Mono<Long> delete(String id, String ownerSubject, String domain) {
        return DomainScope.isUnscoped(domain)
                ? repo.deleteByIdAndOwnerSubject(id, ownerSubject)
                : repo.deleteByIdAndOwnerSubjectAndDomain(id, ownerSubject, domain);
    }

    /** ACTIVE-guarded, owner-scoped visibility write. ZERO rows when the id is unknown,
     *  foreign, OR the row is revoked — the service diagnoses which (404 vs 409). */
    public Mono<Integer> setVisibilityWhereActive(String id, String ownerSubject, String visibility) {
        return repo.setVisibilityWhereActive(id, ownerSubject, visibility);
    }

    /** ACTIVE-guarded bridge status write, keyed by CANONICAL node id (the bridge has no
     *  row ids). ZERO rows = unknown node id or revoked row (the batch's fail-soft
     *  "ignored" leg). Values are service-clamped BEFORE this runs. */
    public Mono<Integer> applyStatusWhereActive(String nodeId, Instant lastSeenAt, Integer batteryPct,
                                                Double snr, Integer hopsAway, String viaDevice) {
        return repo.applyStatusWhereActive(nodeId, lastSeenAt, batteryPct, snr, hopsAway, viaDevice);
    }

    /**
     * The bridge export: every ACTIVE row ACROSS owners and domains (the mesh↔Matrix
     * bridge is platform-level), oldest first. Returns the ROW shape — the caller
     * ({@link InternalMeshDeviceController}, SERVICE-principal only) needs
     * {@code owner_subject} to resolve the owner's Matrix localpart, which is exactly the
     * field the user-facing wire record deliberately omits. REVOKED rows are excluded at
     * the SQL layer: a pulled device must vanish from the bridge mapping immediately.
     */
    public Flux<MeshDeviceEntity> listActiveForBridge() {
        return repo.findByStateOrderByCreatedAtAsc(MeshDevice.STATE_ACTIVE);
    }

    // ── Moderation (SERVICE-gated; cross-owner, optionally brand-scoped) ──

    /** Hard server-side cap on the moderator console page size — a caller-supplied
     *  {@code ?limit=} is clamped to this ceiling so a console read can never stream the
     *  whole {@code mesh_device} table into memory (the same unbounded-table posture
     *  mod-bff's {@code ModActionRepository.MAX_AUDIT_LIMIT} takes). */
    public static final int MAX_MODERATION_LIMIT = 500;

    /** Console page size when the caller supplies no {@code ?limit=}. */
    public static final int DEFAULT_MODERATION_LIMIT = 100;

    /**
     * Clamp a caller-influenced console page size to {@code [1, MAX_MODERATION_LIMIT]}
     * (a non-positive value falls back to the default). Defense-in-depth: the controller
     * clamps the query parameter, the service clamps again, and this facade clamps a
     * THIRD time so no caller — present or future — can reach the SQL {@code LIMIT}
     * unbounded.
     */
    public static int clampModerationLimit(int limit) {
        if (limit < 1) return DEFAULT_MODERATION_LIMIT;
        return Math.min(limit, MAX_MODERATION_LIMIT);
    }

    /**
     * The MODERATOR console read: rows ACROSS every owner, newest claim first, BOUNDED.
     * Returns the ROW shape (not the user-facing wire record) because the console needs
     * exactly the fields that record deliberately omits — {@code owner_subject} (which
     * the caller resolves to a Matrix localpart) and {@code revoked_by} (the acting
     * moderator, hidden from the end user but shown to moderators).
     *
     * @param state  {@code active}|{@code revoked} to filter, or {@code null} for both
     * @param domain the moderator's brand, or {@code null} for the SUPERADMIN
     *               cross-domain view (same unscoped convention as {@link #delete})
     * @param limit  caller-influenced page size, clamped here to the hard cap
     */
    public Flux<MeshDeviceEntity> listForModeration(String state, String domain, int limit) {
        int capped = clampModerationLimit(limit);
        boolean unscoped = DomainScope.isUnscoped(domain);
        if (state == null) {
            return unscoped ? repo.findForModerationNewest(capped)
                    : repo.findForModerationByDomainNewest(domain, capped);
        }
        return unscoped ? repo.findForModerationByStateNewest(state, capped)
                : repo.findForModerationByStateAndDomainNewest(state, domain, capped);
    }

    /**
     * The moderator's single-row read — the DIAGNOSE leg behind a zero-row CAS (was the
     * id unknown, or was the row simply in the wrong state?). BRAND-scoped when
     * {@code domain} is set, so a branded moderator's 409-vs-404 answer can never confirm
     * that another brand's device exists; {@code null} domain is the SUPERADMIN
     * cross-domain read. Row shape for the same reason as {@link #listForModeration}.
     */
    public Mono<MeshDeviceEntity> findForModeration(String id, String domain) {
        return DomainScope.isUnscoped(domain)
                ? repo.findById(id)
                : repo.findByIdAndDomain(id, domain);
    }

    /** ACTIVE-guarded moderator REVOKE (CAS {@code active}→{@code revoked}), stamping
     *  {@code revoked_by}/{@code revoked_at}/{@code revoke_reason}. ZERO rows when the id
     *  is unknown, out of the moderator's brand, OR already revoked — the service
     *  diagnoses which (404 vs 409). */
    public Mono<Integer> revokeWhereActive(String id, String domain, String moderator, String reason) {
        return DomainScope.isUnscoped(domain)
                ? repo.revokeWhereActive(id, moderator, reason)
                : repo.revokeWhereActiveInDomain(id, domain, moderator, reason);
    }

    /** REVOKED-guarded moderator RESTORE (CAS {@code revoked}→{@code active}), CLEARING
     *  the {@code revoked_by}/{@code revoked_at}/{@code revoke_reason} trio. ZERO rows
     *  when the id is unknown, out of the moderator's brand, OR not revoked — the service
     *  diagnoses which (404 vs 409). */
    public Mono<Integer> restoreWhereRevoked(String id, String domain) {
        return DomainScope.isUnscoped(domain)
                ? repo.restoreWhereRevoked(id)
                : repo.restoreWhereRevokedInDomain(id, domain);
    }
}
