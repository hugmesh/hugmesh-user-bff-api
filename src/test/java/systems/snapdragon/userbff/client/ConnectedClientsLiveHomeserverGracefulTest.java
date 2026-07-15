package systems.snapdragon.userbff.client;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.boot.webflux.test.autoconfigure.WebFluxTest;
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
import systems.snapdragon.userbff.auth.AdminBffInternalClient;
import systems.snapdragon.userbff.config.SecurityConfig;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

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

    @Autowired ApplicationContext context;
    WebTestClient client;

    // Spring Security 7: the mockJwt()/mock* reactive mutators only inject the
    // SecurityContext when the springSecurity() configurer's MutatorFilter is in the
    // chain. A @WebFluxTest-autowired client lacks it (mutator dropped -> 401), so build
    // the client from the ApplicationContext with .apply(springSecurity()).
    @org.junit.jupiter.api.BeforeEach
    void setUpSecuredWebTestClient() {
        client = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }
    @Autowired ConfigurableSeam matrixSeam;
    @Autowired ConfigurableSeam mastodonSeam;

    @MockitoBean ReactiveJwtDecoder jwtDecoder;
    @MockitoBean ConnectedClientAuditRepository repo;
    @MockitoBean RevocationWriter revocations;
    // Only consulted when a mockJwt() carries no synthetic "localpart" claim — every JWT
    // this file mints carries one (see listAsMatrixExternalClient / the MASTODON-role
    // test), so this mock is never invoked; still required for context wiring since the
    // controller now takes it as a constructor dependency, and this test's concern is the
    // homeserver-seam merge behavior, not localpart resolution.
    @MockitoBean AdminBffInternalClient adminBff;

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
                        .jwt(j -> j.subject("alice").claim("preferred_username", "alice").claim("localpart", "alice"))
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
         * REGRESSION (Matrix/Mastodon fold divergence — the class of bug this whole fix
         * exists to close): the Matrix and Mastodon legs of a connected-clients call MUST
         * resolve their localparts INDEPENDENTLY, never share one value. {@code
         * ServiceTokenBroker.mastodonLocalpart} folds {@code [^a-z0-9_]} to {@code _}, so a
         * dotted Matrix localpart like {@code john.doe} is a DIFFERENT, independently
         * collision-checked value from its Mastodon-folded form {@code john_doe} (admin-bff
         * Liquibase changeset 291). A caller whose synthetic session carries both claims
         * distinctly must have the MATRIX seam driven with the matrix claim and the
         * MASTODON seam driven with the mastodon claim — never the matrix value re-used
         * for mastodon (which is exactly what a single-resolution port of the
         * MatrixProxyController pattern would silently do, and did in an earlier revision
         * of this fix before an adversarial review caught it).
         */
        @Test
        void bothPlatformsEnabled_matrixAndMastodonLocalpartsDiffer_eachSeamGetsItsOwnFold() {
            when(repo.listForOwner(anyString(), any())).thenReturn(Flux.empty());
            matrixSeam.mode = ConfigurableSeam.Mode.OK;
            mastodonSeam.mode = ConfigurableSeam.Mode.OK;

            client.mutateWith(mockJwt()
                            // A realistic synthetic bff_-session JWT: BOTH claims present and
                            // DELIBERATELY DIFFERENT, exactly as BffSessionAuthenticationWebFilter
                            // threads them from the two independently-collision-checked
                            // AccountView columns.
                            .jwt(j -> j.subject("erin")
                                    .claim("localpart", "john.doe")
                                    .claim("mastodon_localpart", "john_doe"))
                            .authorities(authorities("ROLE_USER",
                                    "ROLE_MATRIX_EXTERNAL_CLIENT", "ROLE_MASTODON_EXTERNAL_CLIENT")))
                    .get().uri("/bff/user/connected-clients")
                    .exchange()
                    .expectStatus().isOk()
                    .expectBodyList(ConnectedClient.class)
                    .hasSize(2)
                    .value(list -> {
                        org.assertj.core.api.Assertions.assertThat(list)
                                .filteredOn(c -> "matrix".equals(c.platform()))
                                .as("the matrix seam must be driven with the MATRIX-fold localpart")
                                .allSatisfy(c -> org.assertj.core.api.Assertions
                                        .assertThat(c.owner()).isEqualTo("john.doe"));
                        org.assertj.core.api.Assertions.assertThat(list)
                                .filteredOn(c -> "mastodon".equals(c.platform()))
                                .as("the mastodon seam must be driven with the MASTODON-fold "
                                        + "localpart, NOT the matrix value")
                                .allSatisfy(c -> org.assertj.core.api.Assertions
                                        .assertThat(c.owner()).isEqualTo("john_doe"));
                    });
        }

        /**
         * REGRESSION (identity-key correctness): a caller whose canonical homeserver
         * localpart cannot be resolved (no synthetic {@code localpart} claim, and
         * admin-bff has no registered account for the identity claims present) must NOT
         * have the live homeserver leg driven with an unchecked/guessed candidate — the
         * live read is skipped entirely and only the durable (owner-keyed, always-safe)
         * audit floor surfaces, even though the seam is healthy and the caller holds the
         * matching external-client role. This is the exact fix for the
         * ConnectedClientsController "revoke doesn't revoke" class of bug: the SAME
         * unresolvable-identity path that here safely degrades a READ is fail-CLOSED on
         * the write side ({@code revoke}, covered elsewhere) rather than ever writing a
         * gateway revocation key under a wrong localpart.
         */
        @Test
        void enabledHealthySeam_callerWithUnresolvableIdentity_liveReadNotAttempted_onlyAuditFloor() {
            when(repo.listForOwner(anyString(), any())).thenReturn(Flux.just(new ConnectedClient(
                    "audit-1", "carol", "matrix", ConnectedClient.KIND_DEVICE,
                    "AUDIT-REF", "Audited Element", Instant.now(), null)));
            matrixSeam.mode = ConfigurableSeam.Mode.OK;   // healthy — would return a live row if driven
            // No "localpart" claim; "preferred_username" present so resolveCanonicalLocalpart
            // actually calls admin-bff (not the zero-claims shortcut) — and admin-bff has no
            // registered account for this identity (Mono.empty(), same effective outcome as a
            // 404 recovered to empty).
            when(adminBff.getAccount("discord:carol")).thenReturn(Mono.empty());

            client.mutateWith(mockJwt()
                            .jwt(j -> j.subject("carol").claim("preferred_username", "carol"))
                            .authorities(authorities("ROLE_USER", "ROLE_MATRIX_EXTERNAL_CLIENT")))
                    .get().uri("/bff/user/connected-clients")
                    .exchange()
                    .expectStatus().isOk()   // degrades gracefully — never a 500 or 401 on the read path
                    .expectBodyList(ConnectedClient.class)
                    .hasSize(1)              // only the audit floor; the live leg was never attempted
                    .value(list -> org.assertj.core.api.Assertions.assertThat(list)
                            .noneSatisfy(c -> org.assertj.core.api.Assertions
                                    .assertThat(c.externalRef()).isEqualTo("LIVE-REF")));
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
                            // "mastodon_localpart" (not "localpart") is the claim consulted for a
                            // MASTODON-role caller — the caller here never touches the matrix leg
                            // at all (filtered out by role before localpartFor is ever called for
                            // it), so no matrix claim/admin-bff stub is needed either way.
                            .jwt(j -> j.subject("alice").claim("mastodon_localpart", "alice"))
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

    /**
     * The WRITE-side counterpart to {@code enabledHealthySeam_callerWithUnresolvableIdentity_
     * liveReadNotAttempted_onlyAuditFloor} above: unlike {@code mine()}'s best-effort READ
     * degrade, {@code revoke()} must fail CLOSED when the canonical localpart cannot be
     * resolved — the localpart keys the DURABLE per-credential gateway revocation entry
     * (the actual enforcement), so writing it under an unresolved/guessed candidate would
     * produce a "revoked": true response that does not actually deny the credential.
     */
    @Nested
    class RevokeFailsClosed {
        @Test
        void revoke_callerWithUnresolvableIdentity_is401_gatewayKeyNeverWritten_auditRowNeverTouched() {
            String id = UUID.randomUUID().toString();
            // The client's PLATFORM is only known once the audit row is found, so the
            // localpart resolution (and its failure) happens AFTER this lookup, not before —
            // a real, active matrix client for this owner+id must resolve here.
            when(repo.find(eq("dave"), eq(id), any())).thenReturn(Mono.just(new ConnectedClient(
                    id, "dave", "matrix", ConnectedClient.KIND_DEVICE,
                    "DEV-DAVE", "Dave's device", Instant.now(), null)));
            // No "localpart" claim; "preferred_username" present so canonicalLocalpart's
            // fallback actually calls admin-bff — which has no registered account for this
            // identity.
            when(adminBff.getAccount("discord:dave")).thenReturn(Mono.empty());

            client.mutateWith(mockJwt()
                            .jwt(j -> j.subject("dave").claim("preferred_username", "dave"))
                            .authorities(authorities("ROLE_USER", "ROLE_MATRIX_EXTERNAL_CLIENT")))
                    .delete().uri("/bff/user/connected-clients/" + id)
                    .exchange()
                    .expectStatus().isUnauthorized();   // fail-closed, NOT a false "revoked": true

            // The audit row WAS looked up (needed to learn the client's platform), but the
            // gateway revocation key write and the final revoked_at stamp were never
            // attempted — the chain errored out at localpart resolution, before either.
            verify(repo).find(eq("dave"), eq(id), any());
            verify(revocations, never()).revokeConnectedClient(any(), any(), any());
            verify(repo, never()).revoke(anyString(), anyString(), any());
        }
    }
}
