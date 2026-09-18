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
import org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.JwtMutator;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.core.publisher.Mono;
import net.hugmesh.authcore.config.SessionCookieService;
import net.hugmesh.userbff.config.BffSessionAuthenticationWebFilter;
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
     *  verbatim on this carrier (recognised by the synthetic token marker), so no
     *  {@code casdoor:} normalisation happens. */
    private static final String ACCOUNT_ID = "google:alice@example.test";

    /** The bare account HANDLE. The filter stamps this as the {@code email} claim for provider
     *  {@code google} (and as {@code preferred_username} for every other provider) — the claim
     *  that USED to win the subject derivation and mis-key the lookup. */
    private static final String HANDLE = "alice@example.test";

    @Autowired ApplicationContext context;
    WebTestClient client;

    @MockitoBean ReactiveJwtDecoder jwtDecoder;
    @MockitoBean AdminBffInternalClient adminBff;
    @MockitoBean HsTokenCustody custody;
    @MockitoBean ServiceTokenBroker broker;
    /** Constructor dependency of the two /bff/register/* legs; those legs are not
     *  exercised by this class, so the default (cookies disabled) stub is enough. */
    @MockitoBean SessionCookieService cookies;

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

    /**
     * The bff_-session synthetic principal EXACTLY as {@code BffSessionAuthenticationWebFilter
     * .syntheticJwt} builds it — <b>including the claim this helper used to omit</b>.
     *
     * <p>The filter stamps ALL of: the non-decodable token-value marker, {@code sub} = the
     * admin-bff account id ({@code provider:handle}), a {@code roles} claim, EITHER
     * {@code email} (provider {@code google}) OR {@code preferred_username} (every other
     * provider) = the bare handle, and the persisted {@code localpart} /
     * {@code mastodon_localpart} when non-blank (changesets 290/291).
     *
     * <p><b>Why the email/preferred_username claim matters here.</b> An earlier revision of this
     * helper built only {@code sub} + the two localpart claims. That is a principal the
     * production filter never emits, and it hid a real defect: {@code CanonicalIdentityResolver
     * .SUBJECT_CLAIMS} reads {@code email} and {@code preferred_username} BEFORE {@code sub}, so
     * with the real claim present the resolver derived the bare handle, normalised it to
     * {@code casdoor:alice@example.test}, and every one of these three paths answered 401 for
     * {@code google:} and {@code discord:} accounts (measured). Only {@code casdoor:} accounts —
     * which is what a cluster happens to hold today — worked. Build the principal the filter
     * builds, or these pins assert nothing about the live carrier.
     */
    private static JwtMutator principalFor(String accountId, String handle, String provider,
                                          String localpart, String mastodonLocalpart,
                                          String... authorities) {
        return mockJwt().jwt(j -> {
            j.tokenValue(BffSessionAuthenticationWebFilter.SYNTHETIC_TOKEN_MARKER + accountId)
                    .header("typ", "bff-synthetic-principal")
                    .subject(accountId)
                    .claim("roles", List.of("user", "matrix", "mastodon"));
            if (handle != null && !handle.isBlank()) {
                if ("google".equalsIgnoreCase(provider)) {
                    j.claim("email", handle);
                } else {
                    j.claim("preferred_username", handle);
                }
            }
            if (localpart != null && !localpart.isBlank()) {
                j.claim("localpart", localpart);
            }
            if (mastodonLocalpart != null && !mastodonLocalpart.isBlank()) {
                j.claim("mastodon_localpart", mastodonLocalpart);
            }
        }).authorities(authorities(authorities));
    }

    /** The default (provider {@code google}) session principal every status pin below rides. */
    private static JwtMutator sessionPrincipal(String... authorities) {
        return principalFor(ACCOUNT_ID, HANDLE, "google", "alice.example", "alice_example",
                authorities);
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

    /**
     * REGRESSION PIN for the defect the old principal helper hid. admin-bff resolves the acting
     * account from the opaque session token ({@code AuthController.me} → {@code store.sessionOf}),
     * so it answers 200 for an account in ANY provider namespace. Parity therefore requires that
     * a {@code bff_} session for a {@code google:} / {@code discord:} / {@code casdoor:} account
     * all resolve to THAT account's id — never to a {@code casdoor:<handle>} normalisation of the
     * {@code email}/{@code preferred_username} claim the filter also stamps.
     *
     * <p>Before the fix, only the {@code casdoor:} row passed (its normalisation happens to
     * reproduce the real key); the other two answered {@code 401 {"error":"login required"}}
     * after asking admin-bff for {@code casdoor:alice@example.test} / {@code casdoor:bob}.
     */
    @Test
    void namespaces_googleAccount_resolvesItsOwnAccountId_notACasdoorNormalisationOfTheEmailClaim() {
        when(adminBff.accountNamespaces(eq("google:alice@example.test")))
                .thenReturn(Mono.just(List.of("forum")));

        client.mutateWith(principalFor("google:alice@example.test", "alice@example.test",
                        "google", "alice.example", "alice_example", "ROLE_USER"))
                .get().uri("/bff/me/namespaces")
                .exchange()
                .expectStatus().isOk()
                .expectBody().json("{\"namespaces\":[\"forum\"]}");
        verify(adminBff, never()).accountNamespaces("casdoor:alice@example.test");
    }

    /** The {@code preferred_username} half of the same defect. */
    @Test
    void namespaces_discordAccount_resolvesItsOwnAccountId_notACasdoorNormalisationOfPreferredUsername() {
        when(adminBff.accountNamespaces(eq("discord:bob")))
                .thenReturn(Mono.just(List.of("wiki")));

        client.mutateWith(principalFor("discord:bob", "bob", "discord",
                        "bob", "bob", "ROLE_USER"))
                .get().uri("/bff/me/namespaces")
                .exchange()
                .expectStatus().isOk()
                .expectBody().json("{\"namespaces\":[\"wiki\"]}");
        verify(adminBff, never()).accountNamespaces("casdoor:bob");
    }

    /** The native-login namespace — the ONLY one that worked before the fix, kept so a
     *  regression that re-breaks the other two cannot hide behind this one still passing. */
    @Test
    void namespaces_casdoorAccount_resolvesItsOwnAccountId() {
        when(adminBff.accountNamespaces(eq("casdoor:carol")))
                .thenReturn(Mono.just(List.of("forum", "wiki")));

        client.mutateWith(principalFor("casdoor:carol", "carol", "casdoor",
                        "carol", "carol", "ROLE_USER"))
                .get().uri("/bff/me/namespaces")
                .exchange()
                .expectStatus().isOk()
                .expectBody().json("{\"namespaces\":[\"forum\",\"wiki\"]}");
    }

    /** A synthetic principal with a blank {@code sub} is a filter-internal bug, not a caller
     *  condition: it must FAIL CLOSED rather than fall through to the claim derivation (which
     *  would key the read to some other account). Mirrors
     *  {@code SessionsService.accountIdFromJwt}'s own stance. */
    @Test
    void namespaces_syntheticPrincipalWithBlankSubject_is401_andNeverFallsThroughToTheEmailClaim() {
        client.mutateWith(mockJwt().jwt(j -> j
                                .tokenValue(BffSessionAuthenticationWebFilter.SYNTHETIC_TOKEN_MARKER)
                                .subject("")
                                .claim("email", HANDLE))
                        .authorities(authorities("ROLE_USER")))
                .get().uri("/bff/me/namespaces")
                .exchange()
                .expectStatus().isUnauthorized();
        verify(adminBff, never()).accountNamespaces(anyString());
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

    /**
     * REGRESSION PIN, provision half. The identity miss 401'd BEFORE the mint, so a
     * {@code google:}/{@code discord:} user could never provision through user-bff at all —
     * and login-ui swallows both provision failures by design
     * ({@code .catch(() =&gt; undefined)}), so the UI showed nothing.
     */
    @Test
    void provisionMatrix_googleAccount_resolvesItsOwnAccountId_andMints() {
        when(adminBff.getAccount(eq(ACCOUNT_ID)))
                .thenReturn(Mono.just(account(true, "alice.example", "alice_example")));
        when(broker.mintMatrix(eq(ACCOUNT_ID), eq("alice.example")))
                .thenReturn(Mono.just(new MintedToken("syt_secret", null, null, "alice.example")));

        client.mutateWith(sessionPrincipal("ROLE_USER", "ROLE_MATRIX"))
                .post().uri("/bff/provision/matrix")
                .exchange()
                .expectStatus().isOk()
                .expectBody().json("{\"ok\":true}");
        verify(adminBff, never()).getAccount("casdoor:" + HANDLE);
        verify(broker).mintMatrix(ACCOUNT_ID, "alice.example");
    }

    /**
     * FAIL-CLOSED pin for the unknown-account leg of {@code requireCompleteAccount}: admin-bff
     * holds no account for this principal, so the internal 404 becomes 401 and <b>nothing is
     * minted</b>.
     *
     * <p>This asserts the {@code switchIfEmpty} specifically, and it is not redundant with the
     * namespaces pin one section up: {@code provision()} composes the gate as
     * {@code requireCompleteAccount(jwt).then(Mono.defer(...))}, and {@code Mono.empty().then(x)}
     * SUBSCRIBES to {@code x} — so dropping that {@code switchIfEmpty} does not merely change a
     * status code, it lets an unknown account proceed into a REAL mint. Reachable on the
     * {@code bff_} carrier because {@code identity.matrixLocalpart} is claim-first and never
     * touches admin-bff, so the missing account would otherwise never be noticed.
     */
    @Test
    void provisionMatrix_unknownAccount_is401_andNothingIsMinted() {
        when(adminBff.getAccount(eq(ACCOUNT_ID))).thenReturn(Mono.error(
                WebClientResponseException.create(404, "Not Found", null, null, null)));
        // Stub the mint to SUCCEED so this pin fails on the mint actually happening, not on a
        // null mock: with the switchIfEmpty removed the request reaches here and returns 200.
        when(broker.mintMatrix(anyString(), anyString()))
                .thenReturn(Mono.just(new MintedToken("syt_secret", null, null, "alice.example")));

        client.mutateWith(sessionPrincipal("ROLE_USER", "ROLE_MATRIX"))
                .post().uri("/bff/provision/matrix")
                .exchange()
                .expectStatus().isUnauthorized();
        verify(broker, never()).mintMatrix(anyString(), anyString());
    }

    /** The same fail-closed leg on the Mastodon path — the two legs share {@code provision()},
     *  but only a pin on each proves the shared helper is actually reached from both. */
    @Test
    void provisionMastodon_unknownAccount_is401_andNothingIsMinted() {
        when(adminBff.getAccount(eq(ACCOUNT_ID))).thenReturn(Mono.error(
                WebClientResponseException.create(404, "Not Found", null, null, null)));
        when(broker.mintMastodon(anyString(), anyString()))
                .thenReturn(Mono.just(new MintedToken("mtd_secret", null, null, "alice_example")));

        client.mutateWith(sessionPrincipal("ROLE_USER", "ROLE_MASTODON"))
                .post().uri("/bff/provision/mastodon")
                .exchange()
                .expectStatus().isUnauthorized();
        verify(broker, never()).mintMastodon(anyString(), anyString());
    }

    /**
     * The SECOND half of the fail-closed brokering gate (divergence 2), which
     * {@link LegacyPathParityControllerDarkTest} cannot reach: {@code app.hs-token.enabled} is
     * TRUE in this slice but the custody cipher key is absent, so a minted token could not be
     * persisted and the mint must not fire at all. Without this pin, deleting
     * {@code || !custody.cipherAvailable()} from the gate ships GREEN (measured).
     */
    @Test
    void provisionMatrix_enabledButNoCustodyCipher_is503_andNothingDownstreamIsTouched() {
        when(custody.cipherAvailable()).thenReturn(false);
        // Everything downstream stubbed to SUCCEED, so a regression that drops the cipher half
        // of the gate fails this pin with 200 + a real mint rather than with a null mock.
        when(adminBff.getAccount(eq(ACCOUNT_ID)))
                .thenReturn(Mono.just(account(true, "alice.example", "alice_example")));
        when(broker.mintMatrix(anyString(), anyString()))
                .thenReturn(Mono.just(new MintedToken("syt_secret", null, null, "alice.example")));

        client.mutateWith(sessionPrincipal("ROLE_USER", "ROLE_MATRIX"))
                .post().uri("/bff/provision/matrix")
                .exchange()
                .expectStatus().isEqualTo(HttpStatus.SERVICE_UNAVAILABLE);
        verify(adminBff, never()).getAccount(anyString());
        verify(broker, never()).mintMatrix(anyString(), anyString());
    }

    /** The Mastodon leg of the same custody gate. */
    @Test
    void provisionMastodon_enabledButNoCustodyCipher_is503_andNothingDownstreamIsTouched() {
        when(custody.cipherAvailable()).thenReturn(false);
        when(adminBff.getAccount(eq(ACCOUNT_ID)))
                .thenReturn(Mono.just(account(true, "alice.example", "alice_example")));
        when(broker.mintMastodon(anyString(), anyString()))
                .thenReturn(Mono.just(new MintedToken("mtd_secret", null, null, "alice_example")));

        client.mutateWith(sessionPrincipal("ROLE_USER", "ROLE_MASTODON"))
                .post().uri("/bff/provision/mastodon")
                .exchange()
                .expectStatus().isEqualTo(HttpStatus.SERVICE_UNAVAILABLE);
        verify(adminBff, never()).getAccount(anyString());
        verify(broker, never()).mintMastodon(anyString(), anyString());
    }

    /** admin-bff: a reserved localpart is 400 at the provision point (defence in depth — the
     *  mint creates a REAL homeserver account). */
    @Test
    void provisionMatrix_reservedLocalpart_is400_andNothingIsMinted() {
        when(adminBff.getAccount(eq(ACCOUNT_ID)))
                .thenReturn(Mono.just(account(true, "admin", "admin")));

        client.mutateWith(principalFor(ACCOUNT_ID, HANDLE, "google", "admin", "admin",
                        "ROLE_USER", "ROLE_MATRIX"))
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
     * PINS A RESIDUAL {@link CanonicalIdentityResolver} ASYMMETRY that this lane deliberately did
     * NOT close, filed as hugmesh-user-bff-api#14. It is NOT the defect the provider pins above
     * cover: {@code ownAccountId} is now synthetic-principal-aware (it honours the {@code sub},
     * which IS the account id, for every provider), but {@code resolveOwnAccount} — a DIFFERENT
     * branch, taken only when the {@code localpart} claim is ABSENT — still derives its key from
     * {@code SUBJECT_CLAIMS} and so probes {@code casdoor:<email-or-preferred_username>}, i.e.
     * {@code casdoor:alice@example.test} for this {@code google:} account. No account is keyed
     * under that, so the caller gets the resolver's 401 ("no registered account for this token's
     * OWN identity") rather than the 409 the raw-JWT carrier above gets.
     *
     * <p><b>Exactly how narrow this is.</b> It is reachable ONLY when the account row's
     * {@code account.localpart} is blank — {@code BffSessionAuthenticationWebFilter} stamps the
     * claim whenever it is not, so on this carrier "claim absent" and "persisted blank" are the
     * same condition — AND the account is in a non-{@code casdoor:} namespace. Both the 401 here
     * and the 409 there are FAIL-CLOSED refusals: the localpart is blank either way, so no mint
     * is reachable down either branch and this is a status/message difference, not a security or
     * availability hole. It is left alone because {@code resolveOwnAccount} is shared by five
     * other mint/custody/revoke call sites and re-pointing it is a change to the shared identity
     * policy, not a parity fix — the operator's call, recorded on the issue.
     */
    @Test
    void provisionMatrix_sessionCarrier_blankLocalpartClaim_is401_theResidualResolverKeyMiss() {
        when(adminBff.getAccount(eq(ACCOUNT_ID)))
                .thenReturn(Mono.just(account(true, "", "")));
        // The key resolveOwnAccount actually probes on this carrier (SUBJECT_CLAIMS-derived from
        // the email claim the filter stamps) — no such account. user-bff-api#14.
        when(adminBff.getAccount(eq("casdoor:" + HANDLE))).thenReturn(Mono.error(
                WebClientResponseException.create(404, "Not Found", null, null, null)));

        client.mutateWith(principalFor(ACCOUNT_ID, HANDLE, "google", "", "",
                        "ROLE_USER", "ROLE_MATRIX"))
                .post().uri("/bff/provision/matrix")
                .exchange()
                .expectStatus().isUnauthorized();
        verify(broker, never()).mintMatrix(anyString(), anyString());
    }
}
