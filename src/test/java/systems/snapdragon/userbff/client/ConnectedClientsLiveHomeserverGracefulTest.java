package systems.snapdragon.userbff.client;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.WebFluxTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.snapdragon.userbff.config.SecurityConfig;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;

/**
 * HTTP-boundary GRACEFUL-DEGRADATION test for the live-homeserver merge behind
 * {@link ConnectedClientsController}: the controller drives the REAL
 * {@link ConnectedClientsService}, which merges the durable {@code connected_client_audit}
 * floor with a BEST-EFFORT per-platform live homeserver read. The durable repo + the
 * gateway revocation writer are mocked; the two {@link HomeserverClientsClient} seams
 * are configurable test doubles so we can flip each platform between the
 * DISABLED (stub, empty stream), ENABLED-OK (returns a live row) and ENABLED-FAILING
 * (throws) states and assert the HTTP response stays graceful.
 *
 * <p>Mission invariant (2): whether the live homeserver leg is disabled OR enabled,
 * the surface returns a graceful 200 — NEVER a 500 — and a live-leg FAILURE is
 * swallowed ({@code onErrorResume}) so only the durable audit floor surfaces. The
 * homeserver is a best-effort transport; it can never break the user's own list.
 *
 * <ul>
 *   <li>DISABLED live seam → 200, only the durable audit row(s);</li>
 *   <li>ENABLED + healthy live seam → 200, audit floor + the live row merged;</li>
 *   <li>ENABLED + FAILING live seam → 200 (not 500), only the audit floor (failure
 *       swallowed);</li>
 *   <li>caller WITHOUT the platform external-client role → the live read is never
 *       attempted even when the seam is enabled (only the audit floor surfaces).</li>
 * </ul>
 */
@WebFluxTest(controllers = ConnectedClientsController.class)
@Import({SecurityConfig.class,
        ConnectedClientsLiveHomeserverGracefulTest.Wiring.class})
class ConnectedClientsLiveHomeserverGracefulTest {

    /**
     * Configurable {@link HomeserverClientsClient} test double for one platform. The
     * {@code mode} field is flipped per test:
     * <ul>
     *   <li>{@code DISABLED} — empty stream (the gated stub: no WebClient wired);</li>
     *   <li>{@code OK} — one live row;</li>
     *   <li>{@code FAILING} — a {@link Flux#error}, simulating an enabled-but-broken
     *       homeserver leg.</li>
     * </ul>
     */
    static final class ConfigurableSeam implements HomeserverClientsClient {
        enum Mode { DISABLED, OK, FAILING }
        private final String platform;
        volatile Mode mode = Mode.DISABLED;

        ConfigurableSeam(String platform) { this.platform = platform; }

        @Override public String platform() { return platform; }

        @Override public Flux<ConnectedClient> list(String localpart, String bearer) {
            return switch (mode) {
                case DISABLED -> Flux.empty();
                case OK -> Flux.just(new ConnectedClient(
                        "live-" + platform, localpart, platform, ConnectedClient.KIND_DEVICE,
                        "LIVE-REF", "Live " + platform + " device", Instant.now(), null));
                case FAILING -> Flux.error(new RuntimeException(
                        "[test] " + platform + " homeserver client-API unreachable"));
            };
        }

        @Override public Mono<Boolean> revoke(String localpart, String externalRef, String bearer) {
            return mode == Mode.FAILING
                    ? Mono.error(new RuntimeException("[test] " + platform + " revoke unreachable"))
                    : Mono.just(mode == Mode.OK);
        }
    }

    @TestConfiguration(proxyBeanMethods = false)
    static class Wiring {
        @Bean ConfigurableSeam matrixSeam() { return new ConfigurableSeam("matrix"); }
        @Bean ConfigurableSeam mastodonSeam() { return new ConfigurableSeam("mastodon"); }

        @Bean ConnectedClientsService connectedClientsService(ConnectedClientAuditRepository repo,
                                                              List<HomeserverClientsClient> seams,
                                                              RevocationWriter rev) {
            return new ConnectedClientsService(repo, seams, rev);
        }
    }

    @Autowired WebTestClient client;
    @Autowired ConfigurableSeam matrixSeam;
    @Autowired ConfigurableSeam mastodonSeam;

    @MockitoBean ReactiveJwtDecoder jwtDecoder;
    @MockitoBean ConnectedClientAuditRepository repo;
    @MockitoBean RevocationWriter revocations;

    @AfterEach
    void resetSeams() {
        matrixSeam.mode = ConfigurableSeam.Mode.DISABLED;
        mastodonSeam.mode = ConfigurableSeam.Mode.DISABLED;
    }

    private static Collection<GrantedAuthority> authorities(String... names) {
        List<GrantedAuthority> out = new ArrayList<>();
        for (String n : names) out.add(new SimpleGrantedAuthority(n));
        return out;
    }

    /** One durable audit row owned by "alice" on matrix (the floor). */
    private void auditFloorForAlice() {
        when(repo.listForOwner(anyString(), any())).thenReturn(Flux.just(new ConnectedClient(
                "audit-1", "alice", "matrix", ConnectedClient.KIND_DEVICE,
                "AUDIT-REF", "Audited Element", Instant.now(), null)));
    }

    private WebTestClient.ResponseSpec listAsMatrixExternalClient() {
        return client.mutateWith(mockJwt()
                        .jwt(j -> j.subject("alice").claim("preferred_username", "alice"))
                        .authorities(authorities("ROLE_USER", "ROLE_MATRIX_EXTERNAL_CLIENT")))
                .get().uri("/bff/user/connected-clients")
                .exchange();
    }

    @Nested
    class Disabled {
        @Test
        void disabledLiveSeam_returnsGraceful200_onlyAuditFloor() {
            auditFloorForAlice();
            // matrixSeam stays DISABLED (default) -> empty live stream
            listAsMatrixExternalClient()
                    .expectStatus().isOk()
                    .expectBodyList(ConnectedClient.class)
                    .hasSize(1)
                    .value(list -> org.assertj.core.api.Assertions.assertThat(list)
                            .anySatisfy(c -> org.assertj.core.api.Assertions
                                    .assertThat(c.externalRef()).isEqualTo("AUDIT-REF")));
        }
    }

    @Nested
    class Enabled {
        @Test
        void enabledHealthyLiveSeam_returns200_auditFloorPlusLiveRow() {
            auditFloorForAlice();
            matrixSeam.mode = ConfigurableSeam.Mode.OK;

            listAsMatrixExternalClient()
                    .expectStatus().isOk()
                    .expectBodyList(ConnectedClient.class)
                    .hasSize(2)
                    .value(list -> org.assertj.core.api.Assertions.assertThat(list)
                            .anySatisfy(c -> org.assertj.core.api.Assertions
                                    .assertThat(c.externalRef()).isEqualTo("AUDIT-REF"))
                            .anySatisfy(c -> org.assertj.core.api.Assertions
                                    .assertThat(c.externalRef()).isEqualTo("LIVE-REF")));
        }

        /**
         * The mission's headline: an ENABLED-BUT-FAILING homeserver leg must NOT
         * surface as a 500. The service's {@code onErrorResume} swallows the live-leg
         * error and the durable audit floor still streams back with a 200.
         */
        @Test
        void enabledFailingLiveSeam_returnsGraceful200_notServerError_onlyAuditFloor() {
            auditFloorForAlice();
            matrixSeam.mode = ConfigurableSeam.Mode.FAILING;

            listAsMatrixExternalClient()
                    .expectStatus().isOk()      // NOT 5xx
                    .expectBodyList(ConnectedClient.class)
                    .hasSize(1)                 // live failure swallowed; only the floor
                    .value(list -> org.assertj.core.api.Assertions.assertThat(list)
                            .allSatisfy(c -> org.assertj.core.api.Assertions
                                    .assertThat(c.externalRef()).isEqualTo("AUDIT-REF")));
        }

        /**
         * Even with a healthy ENABLED seam, a caller lacking that platform's
         * external-client role never drives the live read — only the audit floor
         * surfaces. (The class @PreAuthorize requires SOME external-client role to
         * reach the surface at all; here the caller holds the MASTODON role, so the
         * MATRIX live seam is filtered out by the service.)
         */
        @Test
        void enabledSeam_callerWithoutThatPlatformRole_liveReadNotAttempted() {
            auditFloorForAlice();
            matrixSeam.mode = ConfigurableSeam.Mode.OK;   // healthy, but caller lacks the matrix ext role

            client.mutateWith(mockJwt()
                            .jwt(j -> j.subject("alice").claim("preferred_username", "alice"))
                            .authorities(authorities("ROLE_USER", "ROLE_MASTODON_EXTERNAL_CLIENT")))
                    .get().uri("/bff/user/connected-clients")
                    .exchange()
                    .expectStatus().isOk()
                    .expectBodyList(ConnectedClient.class)
                    .hasSize(1)   // only the audit floor; the matrix live row is NOT pulled
                    .value(list -> org.assertj.core.api.Assertions.assertThat(list)
                            .noneSatisfy(c -> org.assertj.core.api.Assertions
                                    .assertThat(c.externalRef()).isEqualTo("LIVE-REF")));
        }
    }
}
