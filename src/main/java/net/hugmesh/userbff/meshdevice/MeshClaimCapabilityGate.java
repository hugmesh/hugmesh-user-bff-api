package net.hugmesh.userbff.meshdevice;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;
import net.hugmesh.commons.web.ApiException;
import net.hugmesh.userbff.auth.AdminBffInternalClient;

/**
 * The per-domain capability gate on mesh-device CLAIMS — the enforcement half of the
 * admin-bff {@code domain_capability} two-key design (capability
 * {@value #CAPABILITY}): a user may register a radio under their own name only when a
 * SUPERADMIN has granted the capability to their domain AND the domain's ADMIN has
 * enabled it (global kill-switch honored). admin-bff owns the truth
 * ({@code GET /bff/internal/domain-capabilities/{domain}/{capability}}); this gate
 * only consults it on the claim path.
 *
 * <p>SHIPS DARK: {@code app.mesh-device.capability-gate.enabled} defaults {@code false}
 * — claims behave exactly as before this class existed. The in-cluster deployment
 * flips it on once admin-bff's capability surface is live. When ENABLED the gate is
 * FAIL-CLOSED: an unreachable/erroring admin-bff (including the internal client's
 * dark-surface stub) DENIES the claim with the same 403 as an un-granted domain —
 * a claim is a rare, retryable operation, and silently waving it through on an
 * outage would let a revoked-capability domain re-register radios mid-incident.
 *
 * <p>An UNSCOPED caller (SUPERADMIN — {@code domain == null} from
 * {@code PrincipalDomain.forScope}) bypasses the gate: superadmins are the granting
 * authority, and there is no single domain row to consult for them. Existing rows are
 * NEVER affected by the gate — it guards new claims only (release/visibility/status
 * stay owner-gated as before; moderation revocation is mod-tooling's job).
 */
@Component
@SuppressFBWarnings(value = "EI_EXPOSE_REP2",
        justification = "Spring constructor injection: the container owns this singleton collaborator and it is never mutated after construction; a defensive copy of a bean is meaningless (not caller-owned mutable data).")
public class MeshClaimCapabilityGate {

    /** The admin-bff {@code domain_capability.capability} key this gate consults. */
    public static final String CAPABILITY = "user-mesh-devices";

    private static final Logger log = LoggerFactory.getLogger(MeshClaimCapabilityGate.class);

    private final AdminBffInternalClient adminBff;
    private final boolean enabled;

    public MeshClaimCapabilityGate(
            AdminBffInternalClient adminBff,
            @Value("${app.mesh-device.capability-gate.enabled:false}") boolean enabled) {
        this.adminBff = adminBff;
        this.enabled = enabled;
    }

    /** A permanently-open gate for tests / callers that need pre-gate behavior. */
    public static MeshClaimCapabilityGate disabled() {
        return new MeshClaimCapabilityGate(new AdminBffInternalClient(null), false);
    }

    /**
     * Completes empty when the claim may proceed; errors with the 403
     * {@link ApiException} otherwise. See the class doc for the
     * dark-default / fail-closed / superadmin-bypass semantics.
     */
    public Mono<Void> requireClaimAllowed(String domain) {
        if (!enabled) {
            return Mono.empty();
        }
        if (domain == null) {
            log.debug("[mesh-claim-gate] unscoped (superadmin) claim — gate bypassed");
            return Mono.empty();
        }
        return adminBff.domainCapabilityActive(domain, CAPABILITY)
                .onErrorResume(e -> denyOnError(domain, e))
                .flatMap(active -> active ? Mono.empty() : deny(domain));
    }

    private Mono<Boolean> denyOnError(String domain, Throwable e) {
        log.warn("[mesh-claim-gate] capability check failed for domain '{}' — failing "
                + "CLOSED: {}", domain, e.toString());
        return Mono.just(false);
    }

    private Mono<Void> deny(String domain) {
        log.info("[mesh-claim-gate] claim denied — '{}' capability not active for "
                + "domain '{}'", CAPABILITY, domain);
        return Mono.error(ApiException.forbidden(
                "mesh-device registration is not enabled for your domain — ask your "
                        + "administrator to enable it"));
    }
}
