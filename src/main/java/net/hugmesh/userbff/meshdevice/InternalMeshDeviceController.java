package net.hugmesh.userbff.meshdevice;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.userbff.auth.AdminBffInternalClient;
import net.hugmesh.userbff.web.ValidationPatterns;

import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * INTERNAL service-to-service surface for the platform's mesh↔Matrix BRIDGE and for
 * MODERATION of claimed radios —
 * {@code GET /bff/user/internal/mesh-devices} (the full node-id → Matrix-localpart
 * mapping), {@code POST /bff/user/internal/mesh-devices/status} (the batch LoRa
 * status write-back), {@code GET .../moderation} (the cross-owner moderator console
 * list) and {@code POST .../{id}/revoke} + {@code POST .../{id}/restore} (the moderation
 * state writes hugmesh-mod-bff-api drives).
 *
 * <p><b>SERVICE-PRINCIPAL ONLY — the whole security story.</b> This sits under the
 * {@code /bff/user/internal/**} prefix, which {@code SecurityConfig} gates to
 * {@code ROLE_SERVICE} EXCLUSIVELY (NOT ADMIN/MOD/USER/SUPERADMIN — the role hierarchy
 * has NO edge to SERVICE, so even SUPERADMIN is denied), and the
 * {@code @PreAuthorize("hasRole('SERVICE')")} here is the defence-in-depth method gate.
 * The mapping pairs radio node ids with Matrix localparts ACROSS every owner and domain
 * (the bridge is platform-level) — data no human JWT may ever read off this service —
 * and the status writer mutates rows the bridge does not own; both are exactly why this
 * must be unreachable by any human token. Same mechanism as
 * {@code InternalCharacterModerationController} / {@code InternalNotificationController}.
 *
 * <h4>GET mapping contract (what the bridge consumes)</h4>
 *
 * <p>A JSON array of {@code {nodeId, localpart, displayName, visibility}}:
 * {@code nodeId} is the CANONICAL {@code !}+lowercase-hex form; {@code localpart} is the
 * owner's canonical Matrix localpart; {@code visibility} is the owner's status-sharing
 * choice ({@code private|friends|channels}) so the bridge can gate status fan-out.
 * ONLY {@code state='active'} rows are exported (excluded at the SQL layer) — a REVOKED
 * device vanishes from the bridge immediately.
 *
 * <p><b>Localpart resolution — why it goes through admin-bff, per owner subject.</b>
 * The user-facing controllers resolve a caller's localpart CLAIM-FIRST off the session
 * JWT ({@code localpart} claim threaded by {@code BffSessionAuthenticationWebFilter}),
 * but THIS endpoint has no user JWT at all (the caller is the bridge's service
 * principal), so each row's {@code owner_subject} is resolved via
 * {@link AdminBffInternalClient#getAccount(String)} — admin-bff owns the account table
 * and its PERSISTED, collision-checked {@code account.localpart} (never a re-derived
 * candidate). The stored {@code owner_subject} of a native-login caller IS the admin-bff
 * account id (the synthetic session JWT's subject is {@code AccountView.id()}), so the
 * lookup is direct. Owners are DEDUPLICATED before resolving (one {@code getAccount} per
 * owner per request, small bounded concurrency) — sensible batching at this scale, no
 * cache to go stale. FAIL-SOFT: a row whose localpart cannot be resolved (admin-bff
 * error/404, a pre-localpart account row, a non-account subject such as a raw Casdoor
 * UUID) is OMITTED from the mapping and logged — the bridge keeps working with every
 * attributable radio. {@code displayName} is the localpart: {@code AccountView} carries
 * no display-name field (its fields are id/provider/handle/registrationComplete/roles/
 * localpart/mastodonLocalpart), so the localpart is the documented fallback.
 *
 * <h4>POST status contract (what the bridge reports)</h4>
 *
 * <p>A JSON array of {@code {nodeId, lastSeenAt, batteryPct, snr, hopsAway, viaDevice}}
 * — one snapshot per radio heard. FAIL-SOFT per element (see
 * {@link MeshDeviceService#applyStatus}): unknown node ids and REVOKED rows are counted
 * {@code ignored}, never an error; out-of-range telemetry is clamped. Responds
 * {@code 200 {"updated": n, "ignored": m}}.
 *
 * <h4>MODERATION contract (what hugmesh-mod-bff-api drives)</h4>
 *
 * <p>{@code GET /moderation} is the moderator CONSOLE list: every device across ALL
 * owners (optionally narrowed by {@code ?state=active|revoked} and ALWAYS by
 * {@code ?domain=} when the calling moderator is branded), newest claim first, BOUNDED by
 * a server-clamped {@code ?limit=} (default
 * {@value MeshDeviceRepository#DEFAULT_MODERATION_LIMIT}, hard cap
 * {@value MeshDeviceRepository#MAX_MODERATION_LIMIT}). Its rows carry BOTH fields the
 * user-facing {@link MeshDevice} record deliberately omits — {@code ownerSubject} (plus
 * the {@code ownerLocalpart} resolved through the SAME dedupe/fail-soft admin-bff path
 * the bridge mapping uses) and {@code revokedBy} — because a moderator must see who owns
 * a radio and who last pulled it.
 *
 * <p>{@code POST /{id}/revoke} ({@code {reason, moderator}}) and
 * {@code POST /{id}/restore} ({@code {moderator}}) are the STATE writes: CAS
 * {@code active}→{@code revoked} (stamping the audit trio) and
 * {@code revoked}→{@code active} (clearing it). Wrong-state is a 409, unknown/out-of-brand
 * id a 404 — the SAME idiom {@code PUT /mesh-devices/{id}/visibility} uses. The
 * {@code moderator} identity travels in the BODY because this caller IS the trusted
 * service principal: mod-bff derives it from the VALIDATED moderator JWT and never from
 * its own caller's payload — there is no human token on this hop to read it off.
 */
@Tag(name = "Mesh-devices (internal bridge + moderation)", description = "SERVICE-PRINCIPAL "
        + "ONLY: the full node-id → Matrix-localpart mapping (active rows only) + the batch "
        + "LoRa status write-back for the mesh↔Matrix bridge, plus the cross-owner "
        + "moderation console list and the revoke/restore state writes mod-bff drives.")
@RestController
@RequestMapping("/bff/user/internal/mesh-devices")
@PreAuthorize("hasRole('SERVICE')")
@Validated
public class InternalMeshDeviceController {

    private static final Logger log = LoggerFactory.getLogger(InternalMeshDeviceController.class);

    /** Bounded per-request concurrency for the per-owner admin-bff account reads. */
    private static final int RESOLVE_CONCURRENCY = 4;

    private final MeshDeviceRepository repo;
    private final MeshDeviceService service;
    private final AdminBffInternalClient adminBff;

    public InternalMeshDeviceController(MeshDeviceRepository repo, MeshDeviceService service,
                                        AdminBffInternalClient adminBff) {
        this.repo = repo;
        this.service = service;
        this.adminBff = adminBff;
    }

    /**
     * One bridge-mapping row: the radio's canonical node id, the owning user's Matrix
     * localpart (the bridge's attribution key), the name to show for the radio's
     * messages ({@code displayName} — currently always the localpart, see the class
     * doc), and the owner's status-sharing {@code visibility}.
     */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record BridgeMapping(String nodeId, String localpart, String displayName,
                                String visibility) {}

    /**
     * One bridge status report for one radio. {@code nodeId} is tolerant-normalized
     * ({@code a1b2c3d4} / {@code !A1B2C3D4} accepted); every other field is nullable
     * telemetry ({@code batteryPct} 0..100, 101 = externally powered).
     */
    public record StatusReport(String nodeId, Instant lastSeenAt, Integer batteryPct,
                               Double snr, Integer hopsAway, String viaDevice) {}

    /**
     * One MODERATOR-console row. A superset of the user-facing {@link MeshDevice} shape
     * by exactly the two fields that record deliberately withholds from an end user:
     * {@code ownerSubject} (who holds the radio — plus the {@code ownerLocalpart}
     * resolved through admin-bff, {@code null} when it cannot be resolved) and
     * {@code revokedBy} (which moderator last pulled it). {@code domain} is carried so a
     * cross-domain SUPERADMIN console can show which brand a row belongs to.
     *
     * <p>This shape exists ONLY on the {@code ROLE_SERVICE} surface — no human JWT can
     * reach an endpoint that returns it, which is why it may carry cross-owner identity
     * at all.
     */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record ModerationView(String id, String nodeId, String label, String ownerSubject,
                                 String ownerLocalpart, String domain, String state,
                                 String visibility, String revokeReason, String revokedBy,
                                 Instant revokedAt, Instant createdAt, Instant lastSeenAt) {

        /** Row + the (possibly {@code null}) resolved localpart → the console shape. */
        static ModerationView of(MeshDeviceEntity e, String ownerLocalpart) {
            return new ModerationView(e.id(), e.nodeId(), e.label(), e.ownerSubject(),
                    ownerLocalpart, e.domain(), e.state(), e.visibility(),
                    e.revokeReason(), e.revokedBy(), e.revokedAt(), e.createdAt(),
                    e.lastSeenAt());
        }
    }

    /**
     * Revoke body. {@code reason} is REQUIRED — it is the text the DEVICE OWNER is shown
     * in their own list, so a revocation without one would leave a user with a dead radio
     * and no explanation; it is capped to the {@code revoke_reason} column width (019).
     * {@code moderator} is the acting moderator's identity for the {@code revoked_by}
     * stamp, supplied by the trusted SERVICE caller (mod-bff reads it off the VALIDATED
     * moderator JWT — never off its own caller's body). {@code domain} is the moderator's
     * brand: present for a per-brand moderator (the write is then brand-scoped at the SQL
     * layer, so a cross-brand id 404s) and OMITTED only for the cross-domain SUPERADMIN.
     *
     * @param reason    the user-facing revocation reason (required, max 255)
     * @param moderator the acting moderator's identity (required, max 255)
     * @param domain    the moderator's brand scope; omit for the cross-domain view
     */
    public record RevokeRequest(
            @NotBlank(message = "reason is required")
            @Size(max = MeshDeviceService.REVOKE_REASON_MAX,
                    message = "reason must be at most 255 chars") String reason,
            @NotBlank(message = "moderator is required")
            @Size(max = MeshDeviceService.MODERATOR_MAX,
                    message = "moderator must be at most 255 chars") String moderator,
            @Size(max = 255, message = "domain is too long") String domain) {}

    /**
     * Restore body. Same {@code moderator} + {@code domain} contract as
     * {@link RevokeRequest}; there is NO reason — a restore CLEARS the moderation trio,
     * and the durable "who restored it and why" lives in mod-bff's {@code mod_action}
     * ledger rather than on this row.
     *
     * @param moderator the acting moderator's identity (required, max 255)
     * @param domain    the moderator's brand scope; omit for the cross-domain view
     */
    public record RestoreRequest(
            @NotBlank(message = "moderator is required")
            @Size(max = MeshDeviceService.MODERATOR_MAX,
                    message = "moderator must be at most 255 chars") String moderator,
            @Size(max = 255, message = "domain is too long") String domain) {}

    @Operation(summary = "FULL mesh-device mapping for the bridge (SERVICE-principal "
            + "only; every ACTIVE claim across all owners and domains). Rows whose "
            + "owner's Matrix localpart cannot be resolved are omitted (fail-soft).")
    @GetMapping
    public Flux<BridgeMapping> fullMapping() {
        return repo.listActiveForBridge()
                .collectList()
                .flatMapMany(this::resolveRows);
    }

    @Operation(summary = "Batch LoRa status write-back from the bridge (SERVICE-principal "
            + "only). Fail-soft per element: unknown node ids / revoked rows are counted "
            + "'ignored'; out-of-range telemetry is clamped. Returns {updated, ignored}.")
    @PostMapping("/status")
    public Mono<Map<String, Object>> applyStatusBatch(@RequestBody List<StatusReport> body) {
        return Flux.fromIterable(body == null ? List.<StatusReport>of() : body)
                .concatMap(r -> service.applyStatus(r.nodeId(), r.lastSeenAt(), r.batteryPct(),
                        r.snr(), r.hopsAway(), r.viaDevice()))
                .reduce(new int[] {0, 0}, (acc, updated) -> {
                    if (updated) acc[0]++; else acc[1]++;
                    return acc;
                })
                .map(acc -> Map.of("updated", acc[0], "ignored", acc[1]));
    }

    // ── MODERATION (the moderator console list + the two state writes) ────────

    @Operation(summary = "MODERATOR console list of mesh devices (SERVICE-principal only; "
            + "every owner, newest claim first). Optional ?state=active|revoked filter and "
            + "?domain= brand scope (omit the domain ONLY for a cross-domain SUPERADMIN "
            + "view); ?limit is server-clamped. Unlike the bridge mapping this KEEPS rows "
            + "whose owner localpart cannot be resolved — a moderator must still see an "
            + "un-attributable radio (ownerLocalpart is then null).")
    @GetMapping("/moderation")
    public Flux<ModerationView> moderationList(
            @RequestParam(required = false)
            @Pattern(regexp = ValidationPatterns.MESH_STATE,
                    message = "state must be active|revoked") String state,
            @RequestParam(required = false)
            @Size(max = 255, message = "domain is too long") String domain,
            @RequestParam(required = false) Integer limit) {
        return service.listForModeration(blankToNull(state), blankToNull(domain), limit)
                .collectList()
                .flatMapMany(this::resolveModerationRows);
    }

    @Operation(summary = "REVOKE a mesh device (SERVICE-principal only; the moderator "
            + "identity comes from the trusted caller's body — mod-bff derives it from the "
            + "validated moderator JWT). CAS active→revoked stamping revoked_by/revoked_at/"
            + "revoke_reason: the radio leaves the bridge mapping, its visibility freezes, "
            + "and its node id stays claimed. Already-revoked is a 409; unknown or "
            + "out-of-brand id a 404.")
    @PostMapping("/{id}/revoke")
    public Mono<ModerationView> revoke(@PathVariable String id,
                                       @Valid @RequestBody RevokeRequest body) {
        return service.revoke(id, blankToNull(body.domain()), body.moderator(), body.reason())
                .flatMap(this::resolveModerationRow);
    }

    @Operation(summary = "RESTORE a revoked mesh device (SERVICE-principal only). CAS "
            + "revoked→active, CLEARING revoked_by/revoked_at/revoke_reason so the owner "
            + "stops seeing a stale reason (mod-bff's mod_action ledger keeps the durable "
            + "record). A device that is not revoked is a 409; unknown or out-of-brand id "
            + "a 404.")
    @PostMapping("/{id}/restore")
    public Mono<ModerationView> restore(@PathVariable String id,
                                        @Valid @RequestBody RestoreRequest body) {
        return service.restore(id, blankToNull(body.domain()), body.moderator())
                .flatMap(this::resolveModerationRow);
    }

    /**
     * Resolve moderation rows to console entries. Same DEDUPE + bounded-concurrency
     * admin-bff lookup as {@link #resolveRows} — deliberately the SAME mechanism, not a
     * second one — but the FAIL-SOFT verdict differs by design: the bridge OMITS a row it
     * cannot attribute (an un-attributable radio is useless to the bridge), whereas the
     * console KEEPS it with a {@code null} {@code ownerLocalpart}. A moderator who cannot
     * see the un-attributable radios cannot revoke them, which is precisely the device a
     * moderator is most likely to be chasing.
     */
    private Flux<ModerationView> resolveModerationRows(List<MeshDeviceEntity> rows) {
        List<String> owners = rows.stream().map(MeshDeviceEntity::ownerSubject).distinct().toList();
        return Flux.fromIterable(owners)
                .flatMap(this::resolveLocalpart, RESOLVE_CONCURRENCY)
                .collectMap(Map.Entry::getKey, Map.Entry::getValue)
                .flatMapMany(byOwner -> Flux.fromIterable(rows)
                        .map(r -> ModerationView.of(r, byOwner.get(r.ownerSubject()))));
    }

    /** The single-row form of {@link #resolveModerationRows} (the revoke/restore
     *  response): one admin-bff account read, same fail-soft null localpart. */
    private Mono<ModerationView> resolveModerationRow(MeshDeviceEntity row) {
        return resolveLocalpart(row.ownerSubject())
                .map(Map.Entry::getValue)
                .map(localpart -> ModerationView.of(row, localpart))
                .defaultIfEmpty(ModerationView.of(row, null));
    }

    /** Query/body strings arrive either absent or blank-from-a-UI; both mean "unset"
     *  (a blank domain must NOT become a brand nobody is in). */
    private static String blankToNull(String s) {
        return (s == null || s.isBlank()) ? null : s.trim();
    }

    /**
     * Resolve the collected ACTIVE rows to bridge-mapping entries: DEDUPE the owner
     * subjects, resolve each owner's localpart ONCE via admin-bff (bounded concurrency),
     * then emit one entry per row whose owner resolved — rows of an unresolvable owner
     * are OMITTED (fail-soft, logged in {@link #resolveLocalpart}). Row order (oldest
     * claim first) is preserved.
     */
    private Flux<BridgeMapping> resolveRows(List<MeshDeviceEntity> rows) {
        List<String> owners = rows.stream().map(MeshDeviceEntity::ownerSubject).distinct().toList();
        return Flux.fromIterable(owners)
                .flatMap(this::resolveLocalpart, RESOLVE_CONCURRENCY)
                .collectMap(Map.Entry::getKey, Map.Entry::getValue)
                .flatMapMany(byOwner -> Flux.fromIterable(rows)
                        .filter(r -> byOwner.containsKey(r.ownerSubject()))
                        .map(r -> {
                            String localpart = byOwner.get(r.ownerSubject());
                            // displayName = localpart: AccountView carries no
                            // display-name field (documented fallback, class doc).
                            return new BridgeMapping(r.nodeId(), localpart, localpart,
                                    r.visibility());
                        }));
    }

    /**
     * One owner subject → {@code (owner, localpart)} entry via admin-bff's account read.
     * EMPTY when admin-bff errors (including the fail-closed disabled stub and an
     * unknown-account 404) or when the account has no persisted localpart yet — never a
     * fabricated/un-collision-checked candidate. Shared by BOTH resolvers; what EMPTY
     * means to each is their own call (the bridge omits the row, the moderation console
     * keeps it with a null localpart — see {@link #resolveModerationRows}), so the log
     * lines here state the resolution failure, not a consequence only one caller has.
     */
    private Mono<Map.Entry<String, String>> resolveLocalpart(String ownerSubject) {
        return adminBff.getAccount(ownerSubject)
                .flatMap(account -> {
                    String localpart = account.localpart();
                    if (localpart == null || localpart.isBlank()) {
                        log.warn("[mesh-devices] owner {} has no persisted Matrix localpart yet — "
                                + "its device rows are not attributable", ownerSubject);
                        return Mono.<Map.Entry<String, String>>empty();
                    }
                    return Mono.just(Map.entry(ownerSubject, localpart));
                })
                .onErrorResume(e -> {
                    log.warn("[mesh-devices] localpart resolution FAILED for owner {} — its device "
                            + "rows are not attributable: {}", ownerSubject, e.toString());
                    return Mono.empty();
                });
    }
}
