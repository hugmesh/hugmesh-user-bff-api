package systems.hugmesh.userbff.meshdevice;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.hugmesh.userbff.auth.AdminBffInternalClient;

import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * INTERNAL service-to-service surface for the platform's mesh↔Matrix BRIDGE —
 * {@code GET /bff/user/internal/mesh-devices} (the full node-id → Matrix-localpart
 * mapping) and {@code POST /bff/user/internal/mesh-devices/status} (the batch LoRa
 * status write-back).
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
 */
@Tag(name = "Mesh-devices (internal bridge)", description = "SERVICE-PRINCIPAL ONLY: the "
        + "full node-id → Matrix-localpart mapping (active rows only) + the batch LoRa "
        + "status write-back for the mesh↔Matrix bridge.")
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
     * EMPTY (the caller then omits that owner's rows) when admin-bff errors (including
     * the fail-closed disabled stub and an unknown-account 404) or when the account has
     * no persisted localpart yet — never a fabricated/un-collision-checked candidate.
     */
    private Mono<Map.Entry<String, String>> resolveLocalpart(String ownerSubject) {
        return adminBff.getAccount(ownerSubject)
                .flatMap(account -> {
                    String localpart = account.localpart();
                    if (localpart == null || localpart.isBlank()) {
                        log.warn("[mesh-devices] owner {} has no persisted Matrix localpart yet — "
                                + "its device rows are omitted from the bridge mapping", ownerSubject);
                        return Mono.<Map.Entry<String, String>>empty();
                    }
                    return Mono.just(Map.entry(ownerSubject, localpart));
                })
                .onErrorResume(e -> {
                    log.warn("[mesh-devices] localpart resolution FAILED for owner {} — its device "
                            + "rows are omitted from the bridge mapping: {}", ownerSubject, e.toString());
                    return Mono.empty();
                });
    }
}
