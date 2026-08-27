package net.hugmesh.userbff.profile;

import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.client.reactive.MockClientHttpRequest;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import org.springframework.web.reactive.function.client.ExchangeStrategies;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.commons.web.ApiException;
import net.hugmesh.userbff.auth.AdminBffInternalClient;
import net.hugmesh.userbff.auth.AdminBffInternalClient.AccountView;
import net.hugmesh.userbff.auth.CanonicalIdentityResolver;
import net.hugmesh.userbff.config.BffSessionAuthenticationWebFilter;
import net.hugmesh.userbff.federation.FederationApiClient;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * END-TO-END on the IDENTITY AXIS for the {@code bff_}-session carrier: what
 * {@link BffSessionAuthenticationWebFilter} stamps onto its synthetic principal, through
 * {@link ProfileController#usernameOf}, all the way to the bytes
 * {@link CasdoorUserClient} puts on the Casdoor wire.
 *
 * <h2>The defect this pins</h2>
 * Casdoor addresses {@code /api/set-password} by {@code <org>/<userName>}, and a Casdoor
 * username can contain neither {@code ':'} nor {@code '@'}. The {@code bff_} principal's
 * {@code sub} is the composite {@code provider:handle} account id, and its
 * {@code preferred_username} claim carried admin-bff's account HANDLE — which is a Gmail
 * ADDRESS for provider {@code google} (where the claim was not stamped at all, so
 * {@code usernameOf} fell through to the composite subject) and an EMAIL for any native
 * account whose id_token carried one ({@code InternalAccountController.subjectFromIdToken}
 * prefers {@code email} over {@code preferred_username}). Every one of those values makes
 * Casdoor answer {@code "The user ... doesn't exist"} — the SAME failure the JWT-subject
 * fix ({@link ProfileServiceCasdoorIdentityTest}) closed, reached by a different value.
 *
 * <p>Each test walks the REAL filter, so a regression anywhere on the chain (claim
 * dropped, precedence reordered, guard weakened) fails here rather than only in a live
 * Casdoor round trip nobody can run offline.
 */
class BffSessionCasdoorAddressTest {

    /** Records the outbound Casdoor requests; always answers 200 {"status":"ok"}. */
    static final class Recorder implements ExchangeFunction {
        final List<ClientRequest> requests = new ArrayList<>();
        final List<String> bodies = new ArrayList<>();
        @Override public Mono<ClientResponse> exchange(ClientRequest request) {
            requests.add(request);
            MockClientHttpRequest sink = new MockClientHttpRequest(HttpMethod.POST, URI.create("http://casdoor.test"));
            request.writeTo(sink, ExchangeStrategies.withDefaults()).block();
            bodies.add(sink.getBodyAsString().block());
            return Mono.just(ClientResponse.create(HttpStatus.OK)
                    .header("Content-Type", "application/json").body("{\"status\":\"ok\"}").build());
        }
    }

    private final Recorder recorder = new Recorder();

    private ProfileService service() {
        return new ProfileService(
                Mockito.mock(UserProfileRepository.class),
                new CasdoorUserClient(WebClient.builder().exchangeFunction(recorder).build(), "hugmesh"),
                Mockito.mock(FederationApiClient.class));
    }

    @SuppressWarnings("unchecked")
    private static ObjectProvider<AdminBffInternalClient> providerOf(AdminBffInternalClient client) {
        ObjectProvider<AdminBffInternalClient> provider = mock(ObjectProvider.class);
        when(provider.getIfAvailable()).thenReturn(client);
        return provider;
    }

    /** The synthetic {@link Jwt} the REAL filter writes for this account view. */
    private static Jwt syntheticJwtFor(AccountView view) {
        AdminBffInternalClient client = mock(AdminBffInternalClient.class);
        when(client.enabled()).thenReturn(true);
        when(client.resolveSession("bff_tok")).thenReturn(
                Mono.just(new AdminBffInternalClient.SessionResolution(view, "active", false)));
        BffSessionAuthenticationWebFilter filter = new BffSessionAuthenticationWebFilter(
                providerOf(client), 3000L, new DomainRegistry("", ""));

        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.post("/bff/user/profile/password")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer bff_tok").build());
        AtomicReference<Authentication> captured = new AtomicReference<>();
        WebFilterChain chain = ex -> ReactiveSecurityContextHolder.getContext()
                .map(SecurityContext::getAuthentication)
                .doOnNext(captured::set)
                .then();
        StepVerifier.create(filter.filter(exchange, chain)).verifyComplete();
        return (Jwt) captured.get().getPrincipal();
    }

    private static AccountView view(String provider, String handle) {
        return new AccountView(provider + ":" + handle, provider, handle, true, List.of("user"), "lp");
    }

    // ── provider google: the assigned defect ─────────────────────────────────────

    @Test
    void googleSession_addressesCasdoorByTheMintedLoginName_neverTheCompositeId() {
        Jwt jwt = syntheticJwtFor(view("google", "alice@example.com"));

        // the composite id is still the SUBJECT (the owner key) — that part is correct...
        assertThat(jwt.getSubject()).isEqualTo("google:alice@example.com");
        // ...and the login name is now carried explicitly, derived exactly as admin-bff's
        // CasdoorAdminClient.ensureUser derived it when it minted the Casdoor user.
        assertThat(jwt.getClaimAsString(CanonicalIdentityResolver.CLAIM_CASDOOR_USERNAME))
                .isEqualTo("alice");

        service().changePassword(jwt.getSubject(), ProfileController.usernameOf(jwt),
                "old-pw", "new-pw").block();

        assertThat(recorder.bodies).hasSize(1);
        assertThat(recorder.bodies.get(0))
                .contains("userName=alice")
                .doesNotContain("google%3A")   // url-encoded "google:" — the composite id
                .doesNotContain("%40");        // url-encoded "@" — an email address
    }

    @Test
    void googleSession_emailChange_addressesTheSameLoginName() {
        Jwt jwt = syntheticJwtFor(view("google", "alice@example.com"));

        service().changeEmail(jwt.getSubject(), ProfileController.usernameOf(jwt),
                "new@example.com").block();

        assertThat(recorder.requests.get(0).url().getQuery()).contains("id=hugmesh/alice");
        assertThat(recorder.requests.get(0).url().getQuery()).doesNotContain("google:");
    }

    @Test
    void discordSession_handleIsAlreadyTheLoginName_unchanged() {
        Jwt jwt = syntheticJwtFor(view("discord", "bob"));

        assertThat(ProfileController.usernameOf(jwt)).isEqualTo("bob");
        service().changePassword(jwt.getSubject(), ProfileController.usernameOf(jwt), "o", "n").block();
        assertThat(recorder.bodies.get(0)).contains("userName=bob").doesNotContain("discord%3A");
    }

    // ── provider casdoor (native login): the wider, already-live half ────────────

    @Test
    void nativeSession_plainHandle_isTheLoginName_andStillWorks() {
        // The pre-existing WORKING case must stay working: when Casdoor's id_token carried no
        // email, admin-bff keyed the account by preferred_username, so the handle IS the name.
        Jwt jwt = syntheticJwtFor(view("casdoor", "alice"));

        assertThat(jwt.getClaimAsString(CanonicalIdentityResolver.CLAIM_CASDOOR_USERNAME))
                .isEqualTo("alice");
        service().changePassword(jwt.getSubject(), ProfileController.usernameOf(jwt), "o", "n").block();
        assertThat(recorder.bodies.get(0)).contains("userName=alice");
    }

    @Test
    void nativeSession_emailKeyedHandle_isRefusedWithAReason_andNothingReachesCasdoor() {
        // admin-bff prefers `email` over `preferred_username` when it keys a native account,
        // so the real login name is GONE — and the email local-part is only a GUESS (Casdoor
        // user "alice_l" may own alice@example.com). Refuse, rather than aim an account write
        // at a user who may not be the caller.
        Jwt jwt = syntheticJwtFor(view("casdoor", "alice@example.com"));

        assertThat(jwt.getClaimAsString(CanonicalIdentityResolver.CLAIM_CASDOOR_USERNAME)).isNull();
        assertThat(ProfileController.usernameOf(jwt)).isNull();

        assertThatThrownBy(() -> service()
                .changePassword(jwt.getSubject(), ProfileController.usernameOf(jwt), "o", "n").block())
                .isInstanceOfSatisfying(ApiException.class, ex -> {
                    assertThat(ex.status()).isEqualTo(HttpStatus.BAD_REQUEST);
                    assertThat(ex.getMessage()).contains("no Casdoor login name");
                });

        assertThat(recorder.requests).isEmpty();
    }

    // ── the defence-in-depth guard, independent of usernameOf ────────────────────

    @Test
    void aCompositeIdHandedStraightToTheService_isRefused_notPutOnTheWire() {
        // usernameOf already filters this, so this is the layer BENEATH it: the guard that
        // holds if a future carrier ever threads a raw subject again — which is exactly how
        // the original defect came back for the bff_ principal after being fixed for the JWT.
        assertThatThrownBy(() -> service()
                .changePassword("google:alice@example.com", "google:alice@example.com", "o", "n").block())
                .isInstanceOfSatisfying(ApiException.class,
                        ex -> assertThat(ex.getMessage()).contains("is not a Casdoor login name"));
        assertThat(recorder.requests).isEmpty();
    }

    @Test
    void aCompositeIdWithNoAtSign_isAlsoRefused() {
        // The ':' half of the guard on its own: a native composite ("casdoor:alice") carries
        // no '@', so only the account-id check can catch it. Without this case a mutation that
        // drops the ':' check and keeps the '@' one survives — measured, not assumed.
        assertThatThrownBy(() -> service()
                .changePassword("casdoor:alice", "casdoor:alice", "o", "n").block())
                .isInstanceOfSatisfying(ApiException.class,
                        ex -> assertThat(ex.getMessage()).contains("is not a Casdoor login name"));
        assertThat(recorder.requests).isEmpty();
    }

    @Test
    void casdoorUsernameClaim_winsOverAValidLookingPreferredUsername() {
        // PRECEDENCE, pinned independently of shape: when both claims are well-formed but
        // DISAGREE, the dedicated login-name claim is authoritative. (Reachable once
        // admin-bff's reserved/confusable gate disambiguates a minted name, e.g. bob -> bob2.)
        Jwt jwt = Jwt.withTokenValue("t").header("alg", "none")
                .subject("discord:bob")
                .claim("preferred_username", "bob")
                .claim(CanonicalIdentityResolver.CLAIM_CASDOOR_USERNAME, "bob2")
                .build();

        assertThat(ProfileController.usernameOf(jwt)).isEqualTo("bob2");
        service().changePassword(jwt.getSubject(), ProfileController.usernameOf(jwt), "o", "n").block();
        assertThat(recorder.bodies.get(0)).contains("userName=bob2").doesNotContain("userName=bob&");
    }

    @Test
    void anEmailHandedStraightToTheService_isRefused_notPutOnTheWire() {
        assertThatThrownBy(() -> service()
                .changeEmail("sub", "alice@example.com", "new@example.com").block())
                .isInstanceOfSatisfying(ApiException.class,
                        ex -> assertThat(ex.getMessage()).contains("is not a Casdoor login name"));
        assertThat(recorder.requests).isEmpty();
    }
}
