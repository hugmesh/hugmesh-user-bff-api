package systems.snapdragon.userbff.config;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.web.reactive.function.client.WebClientRequestException;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import systems.snapdragon.userbff.auth.AdminBffInternalClient;
import systems.snapdragon.userbff.auth.AdminBffInternalClient.AccountView;

import java.time.Duration;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit contract for {@link BffSessionAuthenticationWebFilter} — the HTTP-introspection
 * counterpart to auth-core's {@code BffCookieAuthenticationWebFilter} (which resolves
 * locally via {@code AccountStore}) and mirrored test-for-test against the gateway's own
 * {@code BffSessionAuthFilterTest} where the behaviour overlaps (token extraction,
 * authority mapping, pass-through / fail-closed rules), but resolving sessions via a
 * mocked {@link AdminBffInternalClient} instead of a mocked WebClient/HTTP hop directly.
 */
class BffSessionAuthenticationWebFilterTest {

    private static final long TEST_TIMEOUT_MS = 500L;

    @SuppressWarnings("unchecked")
    private static ObjectProvider<AdminBffInternalClient> providerOf(AdminBffInternalClient client) {
        ObjectProvider<AdminBffInternalClient> provider = mock(ObjectProvider.class);
        when(provider.getIfAvailable()).thenReturn(client);
        return provider;
    }

    private static AdminBffInternalClient enabledClient() {
        AdminBffInternalClient client = mock(AdminBffInternalClient.class);
        when(client.enabled()).thenReturn(true);
        return client;
    }

    private static BffSessionAuthenticationWebFilter filter(AdminBffInternalClient client) {
        return new BffSessionAuthenticationWebFilter(providerOf(client), TEST_TIMEOUT_MS);
    }

    /**
     * Captures the {@link Authentication} present in the downstream {@link
     * SecurityContext}, and — critically — COUNTS invocations rather than just flagging
     * a boolean: a filter bug that calls {@code chain.filter(exchange)} twice (e.g. a
     * stray {@code switchIfEmpty} chained after a {@code Mono<Void>}-returning flatMap,
     * which is ALWAYS "empty" since {@code Void} never emits {@code onNext}) would look
     * identical to a single call under a boolean flag, but doubles every downstream side
     * effect and, in production, fails outright once the response is already committed.
     * See {@link #doubleInvocationBug_wouldBeCaught_byForwardedCount()} below, which
     * proves this test shape actually catches that exact bug class.
     */
    private static final class CapturingChain implements WebFilterChain {
        final AtomicInteger forwarded = new AtomicInteger(0);
        final AtomicReference<Authentication> auth = new AtomicReference<>();

        @Override
        public Mono<Void> filter(ServerWebExchange exchange) {
            forwarded.incrementAndGet();
            return ReactiveSecurityContextHolder.getContext()
                    .map(SecurityContext::getAuthentication)
                    .doOnNext(auth::set)
                    .then();
        }
    }

    // ── happy path: Authorization header ─────────────────────────────────────

    @Test
    void bearerHeader_validToken_populatesSecurityContext() {
        AccountView view = new AccountView("acct-1", "native", "user1", true, List.of("user", "admin"));
        AdminBffInternalClient client = enabledClient();
        when(client.getAccountBySession("bff_abc123")).thenReturn(Mono.just(view));

        BffSessionAuthenticationWebFilter f = filter(client);
        MockServerHttpRequest req = MockServerHttpRequest.get("/bff/user/profile")
                .header(HttpHeaders.AUTHORIZATION, "Bearer bff_abc123")
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(req);
        CapturingChain chain = new CapturingChain();

        StepVerifier.create(f.filter(exchange, chain)).verifyComplete();

        assertThat(chain.forwarded.get()).isEqualTo(1);
        assertThat(chain.auth.get()).isNotNull();
        assertThat(chain.auth.get().isAuthenticated()).isTrue();
        assertThat(chain.auth.get().getName()).isEqualTo("acct-1");

        var authorities = chain.auth.get().getAuthorities().stream().map(a -> a.getAuthority()).toList();
        assertThat(authorities).containsExactlyInAnyOrder("ROLE_USER", "ROLE_ADMIN");
    }

    // ── happy path: bff_session cookie ────────────────────────────────────────

    @Test
    void cookie_validToken_populatesSecurityContext() {
        AccountView view = new AccountView("acct-2", "native", "user2", true, List.of("user"));
        AdminBffInternalClient client = enabledClient();
        when(client.getAccountBySession("bff_cookieval")).thenReturn(Mono.just(view));

        BffSessionAuthenticationWebFilter f = filter(client);
        MockServerHttpRequest req = MockServerHttpRequest.get("/bff/me")
                .cookie(new HttpCookie("bff_session", "bff_cookieval"))
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(req);
        CapturingChain chain = new CapturingChain();

        StepVerifier.create(f.filter(exchange, chain)).verifyComplete();

        assertThat(chain.forwarded.get()).isEqualTo(1);
        assertThat(chain.auth.get()).isNotNull();
        assertThat(chain.auth.get().getName()).isEqualTo("acct-2");
    }

    // ── no bff_ token: Casdoor JWT bearer → pass-through, no admin-bff call ───

    @Test
    void casdoorJwtBearer_isNotABffToken_passesThrough_withoutCallingAdminBff() {
        AdminBffInternalClient client = enabledClient();
        BffSessionAuthenticationWebFilter f = filter(client);

        MockServerHttpRequest req = MockServerHttpRequest.get("/bff/user/profile")
                .header(HttpHeaders.AUTHORIZATION, "Bearer eyJhbGciOiJSUzI1NiJ9....")
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(req);
        CapturingChain chain = new CapturingChain();

        StepVerifier.create(f.filter(exchange, chain)).verifyComplete();

        assertThat(chain.forwarded.get()).isEqualTo(1);
        assertThat(chain.auth.get()).isNull();
        verify(client, never()).getAccountBySession(anyString());
    }

    // ── no token at all → pass-through ────────────────────────────────────────

    @Test
    void noToken_passesThrough_unauthenticated() {
        AdminBffInternalClient client = enabledClient();
        BffSessionAuthenticationWebFilter f = filter(client);

        MockServerHttpRequest req = MockServerHttpRequest.get("/bff/user/profile").build();
        MockServerWebExchange exchange = MockServerWebExchange.from(req);
        CapturingChain chain = new CapturingChain();

        StepVerifier.create(f.filter(exchange, chain)).verifyComplete();

        assertThat(chain.forwarded.get()).isEqualTo(1);
        assertThat(chain.auth.get()).isNull();
        verify(client, never()).getAccountBySession(anyString());
    }

    // ── no AdminBffInternalClient bean available (e.g. a slice-test context) ──

    @Test
    void noClientAvailable_passesThrough_unauthenticated() {
        BffSessionAuthenticationWebFilter f = new BffSessionAuthenticationWebFilter(providerOf(null), TEST_TIMEOUT_MS);

        MockServerHttpRequest req = MockServerHttpRequest.get("/bff/user/profile")
                .header(HttpHeaders.AUTHORIZATION, "Bearer bff_abc123")
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(req);
        CapturingChain chain = new CapturingChain();

        StepVerifier.create(f.filter(exchange, chain)).verifyComplete();

        assertThat(chain.forwarded.get()).isEqualTo(1);
        assertThat(chain.auth.get()).isNull();
    }

    // ── client present but disabled (dark OIDC surface, app.bff.oidc.enabled=false) ──

    @Test
    void clientDisabled_passesThrough_unauthenticated_withoutCallingGetAccountBySession() {
        AdminBffInternalClient client = mock(AdminBffInternalClient.class);
        when(client.enabled()).thenReturn(false);

        BffSessionAuthenticationWebFilter f = filter(client);
        MockServerHttpRequest req = MockServerHttpRequest.get("/bff/user/profile")
                .header(HttpHeaders.AUTHORIZATION, "Bearer bff_abc123")
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(req);
        CapturingChain chain = new CapturingChain();

        StepVerifier.create(f.filter(exchange, chain)).verifyComplete();

        assertThat(chain.forwarded.get()).isEqualTo(1);
        assertThat(chain.auth.get()).isNull();
        // The disabled stub's getAccountBySession() would throw IllegalStateException —
        // proving it's never even called is what makes this pass-through deliberate
        // rather than accidental (see class doc "Fail-closed posture").
        verify(client, never()).getAccountBySession(anyString());
    }

    // ── unknown/expired session (admin-bff 401, mapped by getAccountBySession) ──

    @Test
    void unknownOrExpiredSession_passesThrough_unauthenticated() {
        AdminBffInternalClient client = enabledClient();
        when(client.getAccountBySession("bff_expired"))
                .thenReturn(Mono.error(new ResponseStatusException(HttpStatus.UNAUTHORIZED, "unknown or expired session")));

        BffSessionAuthenticationWebFilter f = filter(client);
        MockServerHttpRequest req = MockServerHttpRequest.get("/bff/user/profile")
                .header(HttpHeaders.AUTHORIZATION, "Bearer bff_expired")
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(req);
        CapturingChain chain = new CapturingChain();

        StepVerifier.create(f.filter(exchange, chain)).verifyComplete();

        assertThat(chain.forwarded.get()).isEqualTo(1);
        assertThat(chain.auth.get()).isNull();
        assertThat(exchange.getResponse().getStatusCode()).isNull(); // not set by this filter
    }

    // ── admin-bff 5xx → fail-closed 503, downstream NEVER reached ─────────────

    @Test
    void adminBff5xx_failsClosed_returns503() {
        AdminBffInternalClient client = enabledClient();
        WebClientResponseException ex500 = WebClientResponseException.create(
                500, "Internal Server Error", HttpHeaders.EMPTY, new byte[0], null);
        when(client.getAccountBySession("bff_sometoken")).thenReturn(Mono.error(ex500));

        BffSessionAuthenticationWebFilter f = filter(client);
        MockServerHttpRequest req = MockServerHttpRequest.get("/bff/user/profile")
                .header(HttpHeaders.AUTHORIZATION, "Bearer bff_sometoken")
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(req);
        CapturingChain chain = new CapturingChain();

        StepVerifier.create(f.filter(exchange, chain)).verifyComplete();

        assertThat(chain.forwarded.get()).isEqualTo(0);
        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.SERVICE_UNAVAILABLE);
    }

    // ── admin-bff unreachable (connection refused) → fail-closed 503 ─────────

    @Test
    void adminBffUnreachable_failsClosed_returns503() {
        AdminBffInternalClient client = enabledClient();
        WebClientRequestException connRefused = new WebClientRequestException(
                new java.net.ConnectException("Connection refused"), org.springframework.http.HttpMethod.GET,
                java.net.URI.create("http://admin-bff/bff/internal/session/introspect"), HttpHeaders.EMPTY);
        when(client.getAccountBySession("bff_sometoken")).thenReturn(Mono.error(connRefused));

        BffSessionAuthenticationWebFilter f = filter(client);
        MockServerHttpRequest req = MockServerHttpRequest.get("/bff/user/profile")
                .header(HttpHeaders.AUTHORIZATION, "Bearer bff_sometoken")
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(req);
        CapturingChain chain = new CapturingChain();

        StepVerifier.create(f.filter(exchange, chain)).verifyComplete();

        assertThat(chain.forwarded.get()).isEqualTo(0);
        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.SERVICE_UNAVAILABLE);
    }

    // ── admin-bff hangs past the bounded timeout → fail-closed 503 ───────────

    @Test
    void introspectionTimesOut_failsClosed_returns503() {
        AdminBffInternalClient client = enabledClient();
        // Never completes — simulates an admin-bff that accepted the connection but
        // never responds. getAccountBySession() itself sets no timeout, so without this
        // filter's own .timeout(...) the request would hang indefinitely.
        when(client.getAccountBySession("bff_hangs")).thenReturn(Mono.never());

        BffSessionAuthenticationWebFilter f = filter(client);
        MockServerHttpRequest req = MockServerHttpRequest.get("/bff/user/profile")
                .header(HttpHeaders.AUTHORIZATION, "Bearer bff_hangs")
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(req);
        CapturingChain chain = new CapturingChain();

        StepVerifier.create(f.filter(exchange, chain))
                .expectSubscription()
                .thenAwait(Duration.ofMillis(TEST_TIMEOUT_MS + 500))
                .verifyComplete();

        assertThat(chain.forwarded.get()).isEqualTo(0);
        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.SERVICE_UNAVAILABLE);
    }

    // ── unexpected non-401 ResponseStatusException → fail-closed 503 too ─────

    @Test
    void unexpectedResponseStatusException_notMapped401_failsClosed503() {
        AdminBffInternalClient client = enabledClient();
        when(client.getAccountBySession("bff_weird"))
                .thenReturn(Mono.error(new ResponseStatusException(HttpStatus.FORBIDDEN, "unexpected")));

        BffSessionAuthenticationWebFilter f = filter(client);
        MockServerHttpRequest req = MockServerHttpRequest.get("/bff/user/profile")
                .header(HttpHeaders.AUTHORIZATION, "Bearer bff_weird")
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(req);
        CapturingChain chain = new CapturingChain();

        StepVerifier.create(f.filter(exchange, chain)).verifyComplete();

        assertThat(chain.forwarded.get()).isEqualTo(0);
        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.SERVICE_UNAVAILABLE);
    }

    // ── incomplete registration → restricted authority set ────────────────────

    @Test
    void incompleteRegistration_onlyRoleUser_noAdminAuthority() {
        AccountView view = new AccountView("acct-3", "native", "newuser", false, List.of("user", "admin"));
        AdminBffInternalClient client = enabledClient();
        when(client.getAccountBySession("bff_newusertoken")).thenReturn(Mono.just(view));

        BffSessionAuthenticationWebFilter f = filter(client);
        MockServerHttpRequest req = MockServerHttpRequest.get("/bff/user/profile")
                .header(HttpHeaders.AUTHORIZATION, "Bearer bff_newusertoken")
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(req);
        CapturingChain chain = new CapturingChain();

        StepVerifier.create(f.filter(exchange, chain)).verifyComplete();

        assertThat(chain.forwarded.get()).isEqualTo(1);
        var authorities = chain.auth.get().getAuthorities().stream().map(a -> a.getAuthority()).toList();
        assertThat(authorities).containsExactly("ROLE_USER");
    }

    // ── ROLE_SERVICE leakage guard (belt-and-suspenders on top of the buildAuthorities
    //    unit tests below) — /bff/user/internal/** is hasRole("SERVICE"); a human-derived
    //    bff_ session must never be able to satisfy it. ────────────────────────────────

    @Test
    void evenIfServiceRoleSomehowPresent_isMappedButNeverGrantedByThisFilterAlone() {
        // admin-bff's own ReservedRoles guard means "service" can never legitimately
        // appear in a human account's roles list (it's bootstrap/reserved-only) — this
        // test proves that EVEN IF it somehow did, the resulting Authentication is
        // exactly what buildAuthorities() says (traced below), so the security posture
        // of /bff/user/internal/** rests entirely on Spring's hasRole("SERVICE") gate
        // correctly matching ROLE_SERVICE, not on this filter silently downgrading it.
        AccountView view = new AccountView("acct-4", "native", "weird", true, List.of("user", "service"));
        var authorities = BffSessionAuthenticationWebFilter.buildAuthorities(view).stream()
                .map(a -> a.getAuthority()).toList();
        // The mapping is honest (ROLE_<UPPER> verbatim) — the actual guarantee that a
        // human caller can never CARRY "service" in the first place is admin-bff's
        // ReservedRoles allowlist, not this filter. Documented here so the two layers
        // of defense are both visible from the test suite.
        assertThat(authorities).contains("ROLE_SERVICE");
    }

    // ── authority mapping unit tests ──────────────────────────────────────────

    @Test
    void buildAuthorities_rolesMappedToUppercase_withFloor() {
        AccountView view = new AccountView("acct-5", "native", "admin", true, List.of("user", "admin", "mod"));
        var authorities = BffSessionAuthenticationWebFilter.buildAuthorities(view).stream()
                .map(a -> a.getAuthority()).toList();

        assertThat(authorities).containsExactlyInAnyOrder("ROLE_USER", "ROLE_ADMIN", "ROLE_MOD");
    }

    @Test
    void buildAuthorities_roleUserInRoles_notDuplicated() {
        AccountView view = new AccountView("acct-6", "native", "u", true, List.of("user"));
        var authorities = BffSessionAuthenticationWebFilter.buildAuthorities(view).stream()
                .map(a -> a.getAuthority()).toList();

        assertThat(authorities).containsExactly("ROLE_USER");
    }

    @Test
    void buildAuthorities_superadmin_isMapped() {
        AccountView view = new AccountView("acct-7", "native", "sa", true, List.of("superadmin"));
        var authorities = BffSessionAuthenticationWebFilter.buildAuthorities(view).stream()
                .map(a -> a.getAuthority()).toList();

        assertThat(authorities).contains("ROLE_SUPERADMIN", "ROLE_USER");
    }

    @Test
    void buildAuthorities_nullRoles_onlyFloor() {
        // AccountView's own accessor override turns a null roles list into List.of(), so
        // this exercises that defensive path end-to-end.
        AccountView view = new AccountView("acct-8", "native", "norow", true, null);
        var authorities = BffSessionAuthenticationWebFilter.buildAuthorities(view).stream()
                .map(a -> a.getAuthority()).toList();

        assertThat(authorities).containsExactly("ROLE_USER");
    }

    @Test
    void buildAuthorities_neverEmitsRoleService_forPlausibleHumanRoleLists() {
        // Defense in depth (BACKGROUND item 6): every combination of ordinary human
        // roles a real AccountView could plausibly carry must never produce
        // ROLE_SERVICE — that authority must come from nowhere but a genuine Casdoor
        // client-credentials token at the JWT layer.
        List<List<String>> plausibleHumanRoleLists = List.of(
                List.of("user"),
                List.of("user", "mod"),
                List.of("user", "admin"),
                List.of("user", "superadmin"),
                List.of("admin", "mod", "user")
        );
        for (List<String> roles : plausibleHumanRoleLists) {
            AccountView view = new AccountView("acct-x", "native", "h", true, roles);
            var authorities = BffSessionAuthenticationWebFilter.buildAuthorities(view).stream()
                    .map(a -> a.getAuthority()).toList();
            assertThat(authorities).as("roles=%s", roles).doesNotContain("ROLE_SERVICE");
        }
    }

    // ── token extraction unit tests ───────────────────────────────────────────

    @Test
    void extractToken_bearerHeader_returnsBffToken() {
        MockServerHttpRequest req = MockServerHttpRequest.get("/").header(HttpHeaders.AUTHORIZATION, "Bearer bff_abc").build();
        assertThat(BffSessionAuthenticationWebFilter.extractToken(MockServerWebExchange.from(req))).isEqualTo("bff_abc");
    }

    @Test
    void extractToken_nonBffBearer_returnsNull() {
        MockServerHttpRequest req = MockServerHttpRequest.get("/")
                .header(HttpHeaders.AUTHORIZATION, "Bearer eyJhbGciOiJSUzI1NiJ9.xyz").build();
        assertThat(BffSessionAuthenticationWebFilter.extractToken(MockServerWebExchange.from(req))).isNull();
    }

    @Test
    void extractToken_cookie_returnsBffToken() {
        MockServerHttpRequest req = MockServerHttpRequest.get("/")
                .cookie(new HttpCookie("bff_session", "bff_cookieval")).build();
        assertThat(BffSessionAuthenticationWebFilter.extractToken(MockServerWebExchange.from(req))).isEqualTo("bff_cookieval");
    }

    @Test
    void extractToken_bearerTakesPrecedenceOverCookie() {
        MockServerHttpRequest req = MockServerHttpRequest.get("/")
                .header(HttpHeaders.AUTHORIZATION, "Bearer bff_fromheader")
                .cookie(new HttpCookie("bff_session", "bff_fromcookie")).build();
        assertThat(BffSessionAuthenticationWebFilter.extractToken(MockServerWebExchange.from(req))).isEqualTo("bff_fromheader");
    }

    @Test
    void extractToken_noTokenAnywhere_returnsNull() {
        MockServerHttpRequest req = MockServerHttpRequest.get("/").build();
        assertThat(BffSessionAuthenticationWebFilter.extractToken(MockServerWebExchange.from(req))).isNull();
    }

    @Test
    void extractToken_nonBearerAuthScheme_notExtracted_fallsThroughToCookie() {
        // Matches the gateway precedent's "return null" branch only when the header
        // uses the Bearer scheme; a non-Bearer Authorization header (e.g. Basic) is not
        // even inspected for a bff_ prefix, so extraction still checks the cookie.
        MockServerHttpRequest req = MockServerHttpRequest.get("/")
                .header(HttpHeaders.AUTHORIZATION, "Basic dXNlcjpwYXNz")
                .cookie(new HttpCookie("bff_session", "bff_fromcookie")).build();
        assertThat(BffSessionAuthenticationWebFilter.extractToken(MockServerWebExchange.from(req))).isEqualTo("bff_fromcookie");
    }

    // ── THE double-invocation regression proof ─────────────────────────────────

    /**
     * Deliberately re-implements the BUGGY {@code
     * resolved.flatMap(...).switchIfEmpty(chain.filter(exchange))} shape inline (NOT by
     * modifying the production filter) and proves the {@link CapturingChain}'s
     * {@code AtomicInteger} count — not a boolean flag — catches it: a boolean would
     * read {@code true} either way and miss this entirely; the count distinguishes 1
     * from 2. This is the same regression class documented in the production filter's
     * class doc ("Exactly-once chain.filter(exchange) invariant") and in auth-core's
     * {@code BffCookieAuthenticationWebFilter}, which shipped it once for real.
     *
     * <p>This test's OWN production-code counterpart — {@link
     * #bearerHeader_validToken_populatesSecurityContext()} above — asserts {@code
     * forwarded.get() == 1} against the ACTUAL filter, so if that exact anti-pattern
     * were ever reintroduced into {@link BffSessionAuthenticationWebFilter#filter}, that
     * test (not just this standalone proof) would fail too.
     */
    @Test
    void doubleInvocationBug_wouldBeCaught_byForwardedCount() {
        Mono<Authentication> resolved = Mono.just(
                (Authentication) new org.springframework.security.authentication.UsernamePasswordAuthenticationToken(
                        "acct-buggy", null, List.of()));

        CapturingChain chain = new CapturingChain();
        Mono<Void> buggyPipeline = resolved
                .flatMap(auth -> chain.filter(mockExchange())
                        .contextWrite(ReactiveSecurityContextHolder.withAuthentication(auth)))
                .switchIfEmpty(chain.filter(mockExchange()));

        StepVerifier.create(buggyPipeline).verifyComplete();

        // The bug: chain.filter() ran twice for a single successful resolution, because
        // Mono<Void> never emits onNext, so switchIfEmpty ALWAYS treats a successful
        // flatMap completion as "empty" too.
        assertThat(chain.forwarded.get())
                .as("the buggy switchIfEmpty-after-flatMap(Mono<Void>) shape double-invokes the chain")
                .isEqualTo(2);
    }

    private static ServerWebExchange mockExchange() {
        return MockServerWebExchange.from(MockServerHttpRequest.get("/bff/user/profile").build());
    }
}
