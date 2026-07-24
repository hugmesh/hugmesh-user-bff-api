package systems.hugmesh.userbff.meshdevice;

import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import systems.hugmesh.commons.web.ApiException;
import systems.hugmesh.userbff.auth.AdminBffInternalClient;

import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * The claim-gate truth table: dark default is a no-op, unscoped (superadmin)
 * bypasses, active allows, inactive denies 403, and ANY client error — including
 * the dark-surface stub — denies 403 (fail-closed). Mirrors the admin-bff side's
 * DomainCapabilityService truth-table test.
 */
class MeshClaimCapabilityGateTest {

    private final AdminBffInternalClient adminBff = mock(AdminBffInternalClient.class);

    private static void expectForbidden(Mono<Void> result) {
        StepVerifier.create(result)
                .expectErrorMatches(e -> e instanceof ApiException api
                        && api.status().value() == 403)
                .verify();
    }

    @Test
    void disabledGateAllowsWithoutConsultingAdminBff() {
        MeshClaimCapabilityGate gate = new MeshClaimCapabilityGate(adminBff, false);
        StepVerifier.create(gate.requireClaimAllowed("brand-a")).verifyComplete();
        verifyNoInteractions(adminBff);
    }

    @Test
    void unscopedSuperadminBypassesTheEnabledGate() {
        MeshClaimCapabilityGate gate = new MeshClaimCapabilityGate(adminBff, true);
        StepVerifier.create(gate.requireClaimAllowed(null)).verifyComplete();
        verifyNoInteractions(adminBff);
    }

    @Test
    void activeCapabilityAllowsTheClaim() {
        when(adminBff.domainCapabilityActive(eq("brand-a"),
                eq(MeshClaimCapabilityGate.CAPABILITY))).thenReturn(Mono.just(true));
        MeshClaimCapabilityGate gate = new MeshClaimCapabilityGate(adminBff, true);
        StepVerifier.create(gate.requireClaimAllowed("brand-a")).verifyComplete();
    }

    @Test
    void inactiveCapabilityDenies403() {
        when(adminBff.domainCapabilityActive(eq("brand-a"),
                eq(MeshClaimCapabilityGate.CAPABILITY))).thenReturn(Mono.just(false));
        MeshClaimCapabilityGate gate = new MeshClaimCapabilityGate(adminBff, true);
        expectForbidden(gate.requireClaimAllowed("brand-a"));
    }

    @Test
    void adminBffErrorFailsClosed403() {
        when(adminBff.domainCapabilityActive(eq("brand-a"),
                eq(MeshClaimCapabilityGate.CAPABILITY)))
                .thenReturn(Mono.error(new IllegalStateException("admin-bff down")));
        MeshClaimCapabilityGate gate = new MeshClaimCapabilityGate(adminBff, true);
        expectForbidden(gate.requireClaimAllowed("brand-a"));
    }

    @Test
    void darkSurfaceStubFailsClosed403() {
        // The real stub client (null WebClient) errors on every call — the gate must
        // map that to deny, not propagate a 500.
        MeshClaimCapabilityGate gate = new MeshClaimCapabilityGate(
                new AdminBffInternalClient(null), true);
        expectForbidden(gate.requireClaimAllowed("brand-a"));
    }
}
