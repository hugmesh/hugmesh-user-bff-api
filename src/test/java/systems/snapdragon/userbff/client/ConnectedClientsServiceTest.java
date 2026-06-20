package systems.snapdragon.userbff.client;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import systems.snapdragon.userbff.federation.FederationHttpClientSsl;
import systems.snapdragon.userbff.support.TestDatabaseConfig;
import systems.snapdragon.commons.web.ApiException;

import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * OWNER-ENFORCEMENT + EXTERNAL-CLIENT-ROLE-GATE + revoke-ordering test for
 * {@link ConnectedClientsService} over the real repository slice (009). The homeserver
 * seams + the gateway revocation writer are STUBS (disabled), so the durable audit row
 * + the gated key-write are the assertions. Covers:
 * <ul>
 *   <li>list is owner-scoped (a user only sees their own audit rows);</li>
 *   <li>revoke without the platform external-client role is a 403 (service leg);</li>
 *   <li>revoke WITH the role: writes the per-credential key (stub), best-effort
 *       upstream (stub), stamps the audit row — and is owner+id scoped;</li>
 *   <li>a non-owner / unknown / already-revoked id is a 404;</li>
 *   <li>the matrix role does not authorise a mastodon revoke (cross-platform 403);</li>
 *   <li>the reconcile-on-removal seam writes the personal-clients key (stub, never
 *       hard-fails).</li>
 * </ul>
 */
@DataR2dbcTest
@Import({TestDatabaseConfig.class, ConnectedClientAuditRepository.class,
        ConnectedClientsServiceTest.Stubs.class})
class ConnectedClientsServiceTest {

    @TestConfiguration(proxyBeanMethods = false)
    static class Stubs {
        @Bean MatrixClientsClient matrix() { return new MatrixClientsClient(null); }       // stub
        @Bean MastodonClientsClient mastodon() { return new MastodonClientsClient(null); } // stub
        /** A revocation writer with the gateway-write disabled (stub) — logs the key,
         *  returns false, never hard-fails. */
        @Bean RevocationWriter revocationWriter() {
            return new RevocationWriter(new FederationHttpClientSsl(), false, "http://gateway");
        }
        @Bean ConnectedClientsService connectedClientsService(ConnectedClientAuditRepository repo,
                                                              List<HomeserverClientsClient> hs,
                                                              RevocationWriter rev) {
            return new ConnectedClientsService(repo, hs, rev);
        }
    }

    @Autowired ConnectedClientsService service;
    @Autowired ConnectedClientAuditRepository repo;

    private static final Set<String> MATRIX_EXT = Set.of("ROLE_USER", "ROLE_MATRIX_EXTERNAL_CLIENT");
    private static final Set<String> MASTODON_EXT = Set.of("ROLE_USER", "ROLE_MASTODON_EXTERNAL_CLIENT");

    @Test
    void list_isOwnerScoped() {
        repo.record("alice", "matrix", ConnectedClient.KIND_DEVICE, "DEV-A", "Element").block();
        repo.record("bob", "matrix", ConnectedClient.KIND_DEVICE, "DEV-B", "Element").block();

        assertThat(service.list("alice", "alice", null, MATRIX_EXT).collectList().block())
                .anySatisfy(c -> assertThat(c.externalRef()).isEqualTo("DEV-A"))
                .noneSatisfy(c -> assertThat(c.externalRef()).isEqualTo("DEV-B"));
    }

    @Test
    void revoke_withoutExternalClientRole_isForbidden403() {
        ConnectedClient c = repo.record("alice", "matrix", ConnectedClient.KIND_DEVICE, "DEV-F", "Element")
                .block();
        // only the ROLE_USER floor — no external-client role
        ApiException ex = catchApiException(
                () -> service.revoke("alice", c.id(), "alice", null, Set.of("ROLE_USER")).block());
        assertThat(ex.status().value()).isEqualTo(403);
        // not revoked
        assertThat(repo.find("alice", c.id()).block().active()).isTrue();
    }

    @Test
    void revoke_withMatchingExternalClientRole_writesKeyStubAndStampsAudit() {
        ConnectedClient c = repo.record("alice", "matrix", ConnectedClient.KIND_DEVICE, "DEV-OK", "Element")
                .block();
        Map<String, Object> out = service.revoke("alice", c.id(), "alice", null, MATRIX_EXT).block();
        assertThat(out).containsEntry("revoked", true)
                .containsEntry("platform", "matrix")
                .containsEntry("revocationKey", "stubbed")   // gateway-write disabled in tests
                .containsEntry("upstream", "stubbed");        // homeserver seam disabled in tests
        assertThat(repo.find("alice", c.id()).block().active()).isFalse();
    }

    @Test
    void revoke_crossPlatformRole_isForbidden403() {
        // a MASTODON external-client role does NOT authorise a matrix revoke
        ConnectedClient c = repo.record("alice", "matrix", ConnectedClient.KIND_DEVICE, "DEV-X", "Element")
                .block();
        ApiException ex = catchApiException(
                () -> service.revoke("alice", c.id(), "alice", null, MASTODON_EXT).block());
        assertThat(ex.status().value()).isEqualTo(403);
    }

    @Test
    void revoke_nonOwnerOrUnknownId_isNotFound404() {
        ConnectedClient aliceClient = repo.record("alice", "matrix", ConnectedClient.KIND_DEVICE, "DEV-N", "x")
                .block();
        // bob cannot revoke alice's client even with the right role + exact id
        ApiException ex = catchApiException(
                () -> service.revoke("bob", aliceClient.id(), "bob", null, MATRIX_EXT).block());
        assertThat(ex.status().value()).isEqualTo(404);
        assertThat(repo.find("alice", aliceClient.id()).block().active()).isTrue();
    }

    @Test
    void revoke_alreadyRevoked_isNotFound404() {
        ConnectedClient c = repo.record("carol", "mastodon", ConnectedClient.KIND_OAUTH_APP, "APP-R", "Tusky")
                .block();
        service.revoke("carol", c.id(), "carol", null, MASTODON_EXT).block();
        ApiException ex = catchApiException(
                () -> service.revoke("carol", c.id(), "carol", null, MASTODON_EXT).block());
        assertThat(ex.status().value()).isEqualTo(404);
    }

    @Test
    void reconcilePersonalClientRevocation_writesKeyStub_neverHardFails() {
        // the seam returns false (gateway-write disabled) rather than throwing
        assertThat(service.reconcilePersonalClientRevocation("matrix", "alice").block()).isFalse();
        assertThat(service.reconcilePersonalClientRevocation("mastodon", "alice").block()).isFalse();
    }

    @Test
    void reconcilePersonalClientRevocation_badPlatform_isBadRequest() {
        ApiException ex = catchApiException(
                () -> service.reconcilePersonalClientRevocation("telegram", "alice").block());
        assertThat(ex.status().value()).isEqualTo(400);
    }

    private static ApiException catchApiException(Runnable r) {
        try {
            r.run();
        } catch (ApiException e) {
            return e;
        }
        throw new AssertionError("expected an ApiException to be thrown");
    }
}
