package net.hugmesh.userbff.auth;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webflux.test.autoconfigure.WebFluxTest;
import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.core.publisher.Mono;
import net.hugmesh.userbff.config.SecurityConfig;
import net.hugmesh.userbff.hsproxy.HsTokenCustody;
import net.hugmesh.userbff.hsproxy.MintedToken;
import net.hugmesh.userbff.hsproxy.ServiceTokenBroker;
import net.hugmesh.userbff.web.ApiExceptionHandler;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * Status-code + body parity pins for {@link LegacyPathParityController} against
 * hugmesh-admin-bff-api's {@code AuthController} (operator decision 25 on
 * hugmesh-generator#347 — "parity first, then retire"). Every assertion here names the
 * admin-bff behaviour it mirrors; a change to one of them is a change to the contract the
 * cluster's fe-gateway route table already points at.
 *
 * <p>The custody store and the homeserver broker are mocked (no live tuwunel/Akkoma) and
 * {@code app.hs-token.enabled} is forced TRUE — the shipped default is also true, but the
 * live-path assertions must not silently become dark-path assertions if that default ever
 * moves. {@link LegacyPathParityControllerDarkTest} pins the dark posture separately (a
 * property cannot be flipped per-test inside one slice context).
 */
@WebFluxTest(controllers = LegacyPathParityController.class)
@org.springframework.context.annotation.Import({SecurityConfig.class, CanonicalIdentityResolver.class,
        ApiExceptionHandler.class})
@TestPropertySource(properties = "app.hs-token.enabled=true")
class LegacyPathParityControllerTest {

    /** The account id a bff_-session synthetic principal carries as its {@code sub}
     *  ({@code provider:handle}) — {@link CanonicalIdentityResolver#ownAccountId} uses it
     *  verbatim, so no {@code casdoor:} normalisation happens on this carrier. */
    private static final String ACCOUNT_ID = "google:alice@example.test";

    @Autowired ApplicationContext context;
    WebTestClient client;

    @MockitoBean ReactiveJwtDecoder jwtDecoder;
    @MockitoBean AdminBffInternalClient adminBff;
    @MockitoBean HsTokenCustody custody;
    @MockitoBean ServiceTokenBroker broker;

    @BeforeEach
    void setUp() {
        // Spring Security 7: the mockJwt() mutator only lands when springSecurity()'s
        // MutatorFilter is in the chain (see HsProxyControllerSecurityTest).
        client = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
        when(custody.cipherAvailable()).thenReturn(true);
    }

    private static Collection<GrantedAuthority> authorities(String... names) {
        List<GrantedAuthority> out = new ArrayList<>();
        for (String n : names) {
            out.add(new SimpleGrantedAuthority(n));
        }
        return out;
    }

    /** An account view as admin-bff's internal {@code AccountOut} would deserialise it. */
    private static AdminBffInternalClient.AccountView account(boolean complete, String localpart,
                                                              String mastodonLocalpart) {
        return new AdminBffInternalClient.AccountView(ACCOUNT_ID, "google", "alice@example.test",
                complete, List.of("user", "matrix", "mastodon"), localpart, mastodonLocalpart);
    }

    /** The bff_-session synthetic principal shape: {@code sub} IS the account id, and the
     *  persisted localparts ride as claims (changesets 290/291), so the resolver is claim-first
     *  and never hops to admin-bff for identity. */
    private static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers
            .JwtMutator sessionPrincipal(String... authorities) {
        return mockJwt().jwt(j -> j.subject(ACCOUNT_ID)
                        .claim("localpart", "alice.example")
                        .claim("mastodon_localpart", "alice_example"))
                .authorities(authorities(authorities));
    }

    // ── GET /bff/me/namespaces ────────────────────────────────────────────────────────────

    /** admin-bff: falls through to {@code anyExchange().authenticated()} → 401. */
    @Test
    void namespaces_anonymous_isUnauthorized() {
        client.get().uri("/bff/me/namespaces").exchange().expectStatus().isUnauthorized();
        verify(adminBff, never()).accountNamespaces(anyString());
    }

    /** admin-bff body: {@code Map.of("namespaces", ns)}. Byte-identical here. */
    @Test
    void namespaces_returnsAdminBffListUnderTheNamespacesKey() {
        when(adminBff.accountNamespaces(eq(ACCOUNT_ID)))
                .thenReturn(Mono.just(List.of("forum", "wiki")));

        client.mutateWith(sessionPrincipal("ROLE_USER"))
                .get().uri("/bff/me/namespaces")
                .exchange()
                .expectStatus().isOk()
                .expectBody().json("{\"namespaces\":[\"forum\",\"wiki\"]}");
    }

    /** An account admin-bff does not hold: admin-bff's own {@code me()} answers 401 (not 404),
     *  so the internal 404 must be mapped to 401 rather than surfaced. */
    @Test
    void namespaces_unknownAccount_is401_notThe404FromTheInternalHop() {
        when(adminBff.accountNamespaces(eq(ACCOUNT_ID))).thenReturn(Mono.error(
                WebClientResponseException.create(404, "Not Found", null, null, null)));

        client.mutateWith(sessionPrincipal("ROLE_USER"))
                .get().uri("/bff/me/namespaces")
                .exchange()
                .expectStatus().isUnauthorized();
    }

    // ── POST /bff/provision/{matrix,mastodon} ─────────────────────────────────────────────

    @Test
    void provisionMatrix_anonymous_isUnauthorized() {
        client.post().uri("/bff/provision/matrix").exchange().expectStatus().isUnauthorized();
        verify(broker, never()).mintMatrix(anyString(), anyString());
    }

    @Test
    void provisionMastodon_anonymous_isUnauthorized() {
        client.post().uri("/bff/provision/mastodon").exchange().expectStatus().isUnauthorized();
        verify(broker, never()).mintMastodon(anyString(), anyString());
    }

    /** admin-bff gates each platform with {@code @PreAuthorize("hasRole('MATRIX')")} /
     *  {@code hasRole('MASTODON')} on top of the authenticated floor. */
    @Test
    void provisionMatrix_withoutMatrixRole_isForbidden() {
        client.mutateWith(sessionPrincipal("ROLE_USER"))
                .post().uri("/bff/provision/matrix")
                .exchange()
                .expectStatus().isForbidden();
        verify(broker, never()).mintMatrix(anyString(), anyString());
    }

    /** No leakage across platforms: a MATRIX-only principal cannot reach the Mastodon leg. */
    @Test
    void provisionMastodon_withMatrixRoleOnly_isForbidden() {
        client.mutateWith(sessionPrincipal("ROLE_USER", "ROLE_MATRIX"))
                .post().uri("/bff/provision/mastodon")
                .exchange()
                .expectStatus().isForbidden();
        verify(broker, never()).mintMastodon(anyString(), anyString());
    }

    /** admin-bff: {@code if (!me.registrationComplete()) forbidden("complete registration first")}.
     *  This is the ONLY gate for a raw Casdoor JWT carrier (whose token says nothing about
     *  registration state), so it is asserted on the message, not just the status. */
    @Test
    void provisionMatrix_registrationIncomplete_is403_withAdminBffsMessage() {
        when(adminBff.getAccount(eq(ACCOUNT_ID)))
                .thenReturn(Mono.just(account(false, "alice.example", "alice_example")));

        client.mutateWith(sessionPrincipal("ROLE_USER", "ROLE_MATRIX"))
                .post().uri("/bff/provision/matrix")
                .exchange()
                .expectStatus().isForbidden()
                .expectBody().jsonPath("$.error").isEqualTo("complete registration first");
        verify(broker, never()).mintMatrix(anyString(), anyString());
    }

    /** Happy path: the broker is called with (owner = JWT subject, persisted localpart) and the
     *  response is the {@code {"ok": true}} shape the generator's mock-bff already answers —
     *  the minted token is NEVER serialised (D6; see the controller's divergence 1). */
    @Test
    void provisionMatrix_mintsUnderThePersistedLocalpart_andNeverReturnsTheToken() {
        when(adminBff.getAccount(eq(ACCOUNT_ID)))
                .thenReturn(Mono.just(account(true, "alice.example", "alice_example")));
        when(broker.mintMatrix(eq(ACCOUNT_ID), eq("alice.example")))
                .thenReturn(Mono.just(new MintedToken("syt_secret", null, null, "alice.example")));

        client.mutateWith(sessionPrincipal("ROLE_USER", "ROLE_MATRIX"))
                .post().uri("/bff/provision/matrix")
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .json("{\"ok\":true}")
                .jsonPath("$.access_token").doesNotExist()
                .jsonPath("$.accessToken").doesNotExist();
        verify(broker).mintMatrix(ACCOUNT_ID, "alice.example");
    }

    /** The Mastodon leg mints under the PERSISTED Mastodon fold (changeset 291), never a
     *  client-side re-fold of the Matrix localpart. */
    @Test
    void provisionMastodon_mintsUnderThePersistedMastodonFold() {
        when(adminBff.getAccount(eq(ACCOUNT_ID)))
                .thenReturn(Mono.just(account(true, "alice.example", "alice_example")));
        when(broker.mintMastodon(eq(ACCOUNT_ID), eq("alice_example")))
                .thenReturn(Mono.just(new MintedToken("mtd_secret", null, null, "alice_example")));

        client.mutateWith(sessionPrincipal("ROLE_USER", "ROLE_MASTODON"))
                .post().uri("/bff/provision/mastodon")
                .exchange()
                .expectStatus().isOk()
                .expectBody().json("{\"ok\":true}");
        verify(broker).mintMastodon(ACCOUNT_ID, "alice_example");
    }

    /** admin-bff: a reserved localpart is 400 at the provision point (defence in depth — the
     *  mint creates a REAL homeserver account). */
    @Test
    void provisionMatrix_reservedLocalpart_is400_andNothingIsMinted() {
        when(adminBff.getAccount(eq(ACCOUNT_ID)))
                .thenReturn(Mono.just(account(true, "admin", "admin")));

        client.mutateWith(mockJwt().jwt(j -> j.subject(ACCOUNT_ID).claim("localpart", "admin"))
                        .authorities(authorities("ROLE_USER", "ROLE_MATRIX")))
                .post().uri("/bff/provision/matrix")
                .exchange()
                .expectStatus().isBadRequest();
        verify(broker, never()).mintMatrix(anyString(), anyString());
    }

    /** admin-bff wraps ANY broker failure as {@code ApiException.badGateway} → 502. */
    @Test
    void provisionMatrix_brokerFailure_is502() {
        when(adminBff.getAccount(eq(ACCOUNT_ID)))
                .thenReturn(Mono.just(account(true, "alice.example", "alice_example")));
        when(broker.mintMatrix(eq(ACCOUNT_ID), eq("alice.example")))
                .thenReturn(Mono.error(new IllegalStateException("matrix mint: no access_token")));

        client.mutateWith(sessionPrincipal("ROLE_USER", "ROLE_MATRIX"))
                .post().uri("/bff/provision/matrix")
                .exchange()
                .expectStatus().isEqualTo(HttpStatus.BAD_GATEWAY);
    }

    /** A broker error that already carries a status (the unconfigured svc-password /
     *  mastodon-email-domain 503s) keeps it — masking those as 502 would read as "the
     *  homeserver is broken" when the truth is "this deploy never provisioned the secret". */
    @Test
    void provisionMastodon_unconfiguredBroker503_isNotMaskedAs502() {
        when(adminBff.getAccount(eq(ACCOUNT_ID)))
                .thenReturn(Mono.just(account(true, "alice.example", "alice_example")));
        when(broker.mintMastodon(eq(ACCOUNT_ID), eq("alice_example")))
                .thenReturn(Mono.error(new org.springframework.web.server.ResponseStatusException(
                        HttpStatus.SERVICE_UNAVAILABLE,
                        "mastodon token brokering unavailable: email domain not configured")));

        client.mutateWith(sessionPrincipal("ROLE_USER", "ROLE_MASTODON"))
                .post().uri("/bff/provision/mastodon")
                .exchange()
                .expectStatus().isEqualTo(HttpStatus.SERVICE_UNAVAILABLE);
    }

    /**
     * RAW Casdoor JWT carrier with no persisted localpart yet: 409, fail closed — never a mint
     * under a guessed candidate ({@link CanonicalIdentityResolver}'s contract). admin-bff
     * instead SELF-HEALS here ({@code AuthController#localpartOf} re-runs
     * {@code AccountLocalpartService.resolveAndPersist}) and mints; user-bff owns no account
     * table and cannot, so this is a 4th deliberate divergence. It is unreachable on the
     * cluster lane in practice: {@code POST /bff/login} routes to user-bff, whose
     * {@code ensureAccount} hop makes admin-bff persist the localpart on EVERY sign-in, so a
     * caller that has a session has a localpart.
     */
    @Test
    void provisionMatrix_rawJwtCarrier_noPersistedLocalpart_is409_andNothingIsMinted() {
        // A real Casdoor access token: bare subject, no ':' — the resolver normalises it to
        // casdoor:<subject>, which is the key admin-bff persisted the account under.
        when(adminBff.getAccount(eq("casdoor:u-1234")))
                .thenReturn(Mono.just(new AdminBffInternalClient.AccountView(
                        "casdoor:u-1234", "casdoor", "alice@example.test", true,
                        List.of("user", "matrix"), "", "")));

        client.mutateWith(mockJwt().jwt(j -> j.subject("u-1234"))
                        .authorities(authorities("ROLE_USER", "ROLE_MATRIX")))
                .post().uri("/bff/provision/matrix")
                .exchange()
                .expectStatus().isEqualTo(HttpStatus.CONFLICT);
        verify(broker, never()).mintMatrix(anyString(), anyString());
    }

    /**
     * PINS AN EXISTING {@link CanonicalIdentityResolver} ASYMMETRY, not a choice this
     * controller makes. On a {@code bff_}-session synthetic principal the {@code sub} IS the
     * account id ({@code provider:handle}); {@code ownAccountId} honours that verbatim, but
     * {@code resolveOwnAccount} — the branch taken when the {@code localpart} claim is ABSENT —
     * unconditionally looks up {@code casdoor:<subject>}, i.e. {@code casdoor:google:alice@…},
     * which no account is keyed under. The caller therefore gets the resolver's 401 ("no
     * registered account for this token's OWN identity"), NOT the 409 the raw-JWT carrier above
     * gets, and not admin-bff's self-heal-and-mint.
     *
     * <p>This is asserted so the behaviour is visible rather than surprising. It is reachable
     * only for an account row whose {@code account.localpart} is blank — {@code
     * BffSessionAuthenticationWebFilter} stamps the claim whenever it is not — which admin-bff
     * documents as "RARE/transient" and which every cluster sign-in repairs. Fixing the
     * asymmetry means changing the shared resolver, which five other mint/custody/revoke call
     * sites depend on; that is deliberately NOT done in this parity lane.
     */
    @Test
    void provisionMatrix_sessionCarrier_blankLocalpartClaim_is401_theResolversCasdoorKeyMiss() {
        when(adminBff.getAccount(eq(ACCOUNT_ID)))
                .thenReturn(Mono.just(account(true, "", "")));
        // The key the resolver actually probes on this carrier — no such account.
        when(adminBff.getAccount(eq("casdoor:" + ACCOUNT_ID))).thenReturn(Mono.error(
                WebClientResponseException.create(404, "Not Found", null, null, null)));

        client.mutateWith(mockJwt().jwt(j -> j.subject(ACCOUNT_ID))
                        .authorities(authorities("ROLE_USER", "ROLE_MATRIX")))
                .post().uri("/bff/provision/matrix")
                .exchange()
                .expectStatus().isUnauthorized();
        verify(broker, never()).mintMatrix(anyString(), anyString());
    }
}
