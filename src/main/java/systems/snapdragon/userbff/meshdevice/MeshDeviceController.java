package systems.snapdragon.userbff.meshdevice;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.snapdragon.userbff.security.PrincipalDomain;
import systems.snapdragon.userbff.web.ValidationPatterns;

/**
 * Owner-scoped Meshtastic mesh-device claims — an authenticated platform user registers
 * a LoRa radio NODE ID under their own identity so the platform's mesh↔Matrix bridge can
 * attribute that radio's messages to them. The owner is ALWAYS the JWT subject — never a
 * body/path field — so a user can only ever list/claim/manage/release their OWN devices.
 * ROLE_USER floor (enforced by SecurityConfig path rules on {@code /bff/user/**}) +
 * {@code @PreAuthorize("hasRole('USER')")} defence-in-depth.
 *
 * <ul>
 *   <li>GET {@code /mesh-devices} — the caller's own claimed devices (newest first),
 *       INCLUDING revoked rows (with state + reason) and the bridge-reported LoRa status
 *       fields;</li>
 *   <li>POST {@code /mesh-devices} — claim a node id. Accepts {@code a1b2c3d4} /
 *       {@code !A1B2C3D4}; the service canonicalizes to {@code !}+lowercase before
 *       storage. A node id already registered by ANYONE (any domain, active OR revoked)
 *       is a 409 — one owner per radio, platform-wide;</li>
 *   <li>PUT {@code /mesh-devices/{id}/visibility} — who may see the device's LoRa
 *       status ({@code private|friends|channels}). Frozen (409) on a revoked row;</li>
 *   <li>DELETE {@code /mesh-devices/{id}} — release the claim. A foreign/unknown id is a
 *       404 (never a 403) — no cross-owner existence leak.</li>
 * </ul>
 */
@Tag(name = "Mesh-devices", description = "The caller's OWN claimed Meshtastic LoRa radio "
        + "node ids (owner = JWT subject). Node ids are globally unique — one owner per radio.")
@RestController
@RequestMapping("/bff/user")
@PreAuthorize("hasRole('USER')")
@Validated
public class MeshDeviceController {

    private final MeshDeviceService devices;
    private final PrincipalDomain principalDomain;

    /**
     * Constructs a {@code MeshDeviceController} with its required collaborators.
     *
     * @param devices         the service that owns claim/normalization/release logic
     * @param principalDomain the helper that derives the brand-domain scope from the JWT issuer
     */
    public MeshDeviceController(MeshDeviceService devices, PrincipalDomain principalDomain) {
        this.devices = devices;
        this.principalDomain = principalDomain;
    }

    // -------------------------------------------------------------------------
    // Request body records
    // -------------------------------------------------------------------------

    /**
     * Claim body. {@code nodeId} (the radio's Meshtastic node id) is required and must
     * be 8 hex digits with an OPTIONAL {@code !} prefix, any case — the ACCEPTED
     * pre-normalization shape ({@link ValidationPatterns#MESH_NODE_ID}); the service
     * stores the canonical {@code !}+lowercase form. {@code label} is an optional
     * user-facing name for the radio.
     *
     * @param nodeId the Meshtastic node id to claim (e.g. {@code !a1b2c3d4} or {@code A1B2C3D4})
     * @param label  optional device label (max 64 chars)
     */
    public record ClaimRequest(
            @NotBlank(message = "nodeId is required")
            @Pattern(regexp = ValidationPatterns.MESH_NODE_ID,
                    message = "nodeId must be exactly 8 hex digits with an optional '!' prefix")
            String nodeId,
            @Size(max = 64, message = "label must be at most 64 chars") String label) {}

    /**
     * Visibility-change body. {@code visibility} must be one of the
     * {@code mesh_device.visibility} vocabulary — mirrors the 019 CHECK +
     * {@code MeshDevice.validVisibility}.
     *
     * @param visibility who may see the device's LoRa status
     *                   ({@code private}, {@code friends}, or {@code channels})
     */
    public record VisibilityRequest(
            @NotBlank(message = "visibility is required")
            @Pattern(regexp = ValidationPatterns.MESH_VISIBILITY,
                    message = "visibility must be private|friends|channels")
            String visibility) {}

    // -------------------------------------------------------------------------
    // Read: list the caller's own devices
    // -------------------------------------------------------------------------

    /**
     * Returns all mesh-device rows owned by the JWT subject (their domain only),
     * including revoked rows and the bridge-reported status fields.
     *
     * @param jwt the already-validated Casdoor JWT (injected by Spring Security)
     * @return a {@link Flux} of the caller's {@link MeshDevice} rows (may be empty)
     */
    @Operation(summary = "List my claimed mesh devices (newest first; revoked rows included "
            + "with state + reason; bridge-reported LoRa status fields included).")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "The caller's own mesh devices (may be empty)."),
        @ApiResponse(responseCode = "401", description = "Missing or invalid Casdoor JWT."),
        @ApiResponse(responseCode = "403", description = "Principal lacks ROLE_USER.")
    })
    @GetMapping("/mesh-devices")
    public Flux<MeshDevice> mine(@AuthenticationPrincipal Jwt jwt) {
        return devices.listMine(jwt.getSubject(), principalDomain.forScope(jwt));
    }

    // -------------------------------------------------------------------------
    // Write: claim a node id
    // -------------------------------------------------------------------------

    /**
     * Claim a Meshtastic node id under the caller. The node id is normalized to the
     * canonical {@code !}+lowercase form in the service; the claim is GLOBALLY unique
     * (one owner per radio, across every user and brand — active or revoked).
     *
     * @param jwt  the already-validated Casdoor JWT
     * @param body the validated claim request (nodeId + optional label)
     * @return a {@link Mono} of the persisted {@link MeshDevice} (canonical nodeId,
     *         visibility {@code private}, state {@code active})
     */
    @Operation(summary = "Claim a Meshtastic LoRa node id (owner = JWT subject). "
            + "Accepts 'a1b2c3d4' / '!A1B2C3D4'; stores the canonical '!'+lowercase form. "
            + "A node id already registered by anyone is a 409.")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Node id claimed; the persisted device is returned (canonical nodeId, visibility 'private', state 'active')."),
        @ApiResponse(responseCode = "400", description = "Missing/malformed nodeId (not 8 hex digits with an optional '!' prefix) or label over 64 chars."),
        @ApiResponse(responseCode = "401", description = "Missing or invalid Casdoor JWT."),
        @ApiResponse(responseCode = "403", description = "Principal lacks ROLE_USER."),
        @ApiResponse(responseCode = "409", description = "Node id already registered on this platform (by anyone, any domain, active or revoked — one owner per radio)."),
        @ApiResponse(responseCode = "500", description = "Database error writing the claim row.")
    })
    @PostMapping("/mesh-devices")
    public Mono<MeshDevice> claim(@AuthenticationPrincipal Jwt jwt,
                                  @Valid @RequestBody ClaimRequest body) {
        // owner = JWT SUBJECT (the row key) — never a body field; domain = the
        // issuer-derived brand. The service normalizes the node id before storage.
        return devices.claim(jwt.getSubject(), principalDomain.forScope(jwt),
                body.nodeId(), body.label());
    }

    // -------------------------------------------------------------------------
    // Write: change a device's status visibility
    // -------------------------------------------------------------------------

    /**
     * Change who may see the device's LoRa status. Owner-scoped; ACTIVE rows only.
     *
     * @param jwt  the already-validated Casdoor JWT
     * @param id   the device row id (the opaque UUID the owner holds)
     * @param body the validated visibility request
     * @return a {@link Mono} of the updated {@link MeshDevice}
     */
    @Operation(summary = "Change who may see MY device's LoRa status "
            + "(private|friends|channels). Frozen on a revoked device (409); a device "
            + "that is not mine is a 404.")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Visibility updated; the device is returned."),
        @ApiResponse(responseCode = "400", description = "visibility not in private|friends|channels."),
        @ApiResponse(responseCode = "401", description = "Missing or invalid Casdoor JWT."),
        @ApiResponse(responseCode = "403", description = "Principal lacks ROLE_USER."),
        @ApiResponse(responseCode = "404", description = "No such mesh device for this user (foreign/unknown id — no existence leak)."),
        @ApiResponse(responseCode = "409", description = "Device is revoked — visibility cannot be changed."),
        @ApiResponse(responseCode = "500", description = "Database error.")
    })
    @PutMapping("/mesh-devices/{id}/visibility")
    public Mono<MeshDevice> setVisibility(@AuthenticationPrincipal Jwt jwt,
                                          @PathVariable String id,
                                          @Valid @RequestBody VisibilityRequest body) {
        return devices.setVisibility(jwt.getSubject(), id,
                principalDomain.forScope(jwt), body.visibility());
    }

    // -------------------------------------------------------------------------
    // Delete: release one of the caller's claims
    // -------------------------------------------------------------------------

    /**
     * Releases one of the caller's mesh-device claims, identified by its row id. The
     * service scopes the delete to the JWT subject (and the caller's domain), so a
     * foreign or unknown id is a 404 — never a 403 (no cross-owner existence leak).
     *
     * @param jwt the already-validated Casdoor JWT
     * @param id  the device row id to release
     * @return a {@link Mono} that completes with HTTP 204 No Content on success
     */
    @Operation(summary = "Release one of MY mesh-device claims (scoped to me + id). "
            + "Releasing a REVOKED row is allowed and frees the node id.")
    @ApiResponses({
        @ApiResponse(responseCode = "204", description = "Claim released."),
        @ApiResponse(responseCode = "401", description = "Missing or invalid Casdoor JWT."),
        @ApiResponse(responseCode = "403", description = "Principal lacks ROLE_USER."),
        @ApiResponse(responseCode = "404", description = "No such mesh device for this user (or wrong domain)."),
        @ApiResponse(responseCode = "500", description = "Database error.")
    })
    @DeleteMapping("/mesh-devices/{id}")
    public Mono<ResponseEntity<Void>> release(@AuthenticationPrincipal Jwt jwt,
                                              @PathVariable String id) {
        return devices.release(jwt.getSubject(), id, principalDomain.forScope(jwt))
                .thenReturn(ResponseEntity.noContent().build());
    }
}
