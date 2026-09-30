package net.hugmesh.userbff.auth;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Mono;
import net.hugmesh.authcore.config.SessionCookieService;
import net.hugmesh.authcore.config.SessionCookieWebFilter;

import java.time.Duration;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * {@link SsoAuthController}'s register / me / session / sessionOut legs delegate every
 * account/session op to a MOCKED {@link AdminBffInternalClient} — there is NO local auth-core
 * AccountStore / BffSessionRepository bean (user-bff has no account/session DB). Bound via
 * {@link WebTestClient#bindToController} (no full context). The native {@code /bff/login} leg
 * has its own {@code NativeLoginControllerTest}.
 */
class SsoAuthControllerTest {

    private static final AdminBffInternalClient.AccountView ACCOUNT =
            new AdminBffInternalClient.AccountView(
                    "acc-1", "email", "alice@example.test", false, List.of("user"), "alice");
    private static final AdminBffInternalClient.SessionView SESSION =
            new AdminBffInternalClient.SessionView("bff_opaque", "acc-1");

    private WebTestClient client(AdminBffInternalClient adminBff, boolean cookieEnabled) {
        SessionCookieService cookies = new SessionCookieService(cookieEnabled, true, Duration.ofHours(12));
        // The native-login collaborators are unused by these register/me/session legs; pass
        // dark stubs so the controller wires. A dark CasdoorLoginClient + a completion service
        // over a null exchange provider both fail closed, but neither is reached here.
        CasdoorLoginClient casdoorLogin = new CasdoorLoginClient(null, "/api/login", "app-user-bff",
                "app-user-bff", "hugmesh", "openid profile email");
        OidcLoginCompletionService completion =
                new OidcLoginCompletionService(NativeLoginControllerTest.provider(null),
                        adminBff, new net.hugmesh.authcore.casdoor.BffCustodyCipher(""), cookies);
        return WebTestClient.bindToController(
                new SsoAuthController(casdoorLogin, completion, adminBff, cookies,
                        "https://hugmesh.net/login/callback")).build();
    }

    @Test
    void register_delegatesAllowlistEnsureAndSession() {
        AdminBffInternalClient adminBff = mock(AdminBffInternalClient.class);
        when(adminBff.allowlistCheck(eq("google"), eq("alice@example.test"))).thenReturn(Mono.just(true));
        when(adminBff.ensureAccount(eq("casdoor"), eq("alice@example.test"))).thenReturn(Mono.just(ACCOUNT));
        when(adminBff.createSession("acc-1")).thenReturn(Mono.just(SESSION));

        client(adminBff, false).post().uri("/bff/register")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"email\":\"alice@example.test\",\"displayName\":\"Alice\",\"screenReaderName\":\"Alice\"}")
                .exchange()
                .expectStatus().isOk()
                .expectBody().jsonPath("$.token").isEqualTo("bff_opaque");

        // #13 defect 2: invite looked up under admin-bff's "google" namespace, account keyed casdoor:.
        verify(adminBff).allowlistCheck("google", "alice@example.test");
        verify(adminBff).ensureAccount("casdoor", "alice@example.test");
        verify(adminBff, never()).allowlistCheck(eq("email"), anyString());
        verify(adminBff, never()).ensureAccount(eq("email"), anyString());
    }

    /**
     * /register (permitAll, account-provisioning) MUST gate on the BFF-side allowlist. An
     * unlisted email is rejected with 403 BEFORE any account is provisioned.
     */
    @Test
    void register_notAllowlisted_is403_andNeverProvisions() {
        AdminBffInternalClient adminBff = mock(AdminBffInternalClient.class);
        when(adminBff.allowlistCheck(eq("google"), eq("blocked@example.test"))).thenReturn(Mono.just(false));

        client(adminBff, false).post().uri("/bff/register")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"email\":\"blocked@example.test\",\"displayName\":\"Mallory\",\"screenReaderName\":\"Mallory\"}")
                .exchange()
                .expectStatus().isForbidden();

        verify(adminBff).allowlistCheck("google", "blocked@example.test");
        verify(adminBff, never()).ensureAccount(anyString(), anyString());
        verify(adminBff, never()).createSession(anyString());
    }

    @Test
    void register_twoDotEmail_isWrappedSoAdminBffDoesNotMisreadItAsAJwt() throws Exception {
        AdminBffInternalClient adminBff = mock(AdminBffInternalClient.class);
        when(adminBff.allowlistCheck(eq("google"), eq("first.last@example.test"))).thenReturn(Mono.just(true));
        org.mockito.ArgumentCaptor<String> handle = org.mockito.ArgumentCaptor.forClass(String.class);
        when(adminBff.ensureAccount(eq("casdoor"), handle.capture())).thenReturn(Mono.just(ACCOUNT));
        when(adminBff.createSession("acc-1")).thenReturn(Mono.just(SESSION));

        client(adminBff, false).post().uri("/bff/register")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"email\":\" First.Last@Example.test \"}")
                .exchange().expectStatus().isOk();

        String[] parts = handle.getValue().split("\\.");
        org.junit.jupiter.api.Assertions.assertEquals(3, parts.length);
        String claims = new String(java.util.Base64.getUrlDecoder().decode(parts[1]),
                java.nio.charset.StandardCharsets.UTF_8);
        org.junit.jupiter.api.Assertions.assertEquals("{\"email\":\"first.last@example.test\"}", claims);
    }

    @Test
    void register_alreadyCompleteAccount_is409_andMintsNoSession() {
        AdminBffInternalClient adminBff = mock(AdminBffInternalClient.class);
        when(adminBff.allowlistCheck(eq("google"), eq("alice@example.test"))).thenReturn(Mono.just(true));
        when(adminBff.ensureAccount(eq("casdoor"), eq("alice@example.test"))).thenReturn(Mono.just(
                new AdminBffInternalClient.AccountView(
                        "casdoor:alice@example.test", "casdoor", "alice@example.test", true,
                        List.of("user"), "alice")));

        client(adminBff, false).post().uri("/bff/register")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"email\":\"alice@example.test\"}")
                .exchange().expectStatus().isEqualTo(409);

        verify(adminBff, never()).createSession(anyString());
    }

    @Test
    void register_allowlistError_failsClosed_andNeverProvisions() {
        AdminBffInternalClient adminBff = mock(AdminBffInternalClient.class);
        when(adminBff.allowlistCheck(anyString(), anyString()))
                .thenReturn(Mono.error(new IllegalStateException("admin-bff down")));

        client(adminBff, false).post().uri("/bff/register")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"email\":\"alice@example.test\"}")
                .exchange().expectStatus().is5xxServerError();

        verify(adminBff, never()).ensureAccount(anyString(), anyString());
        verify(adminBff, never()).createSession(anyString());
    }

    @Test
    void register_blankEmail_is400_andCallsNothing() {
        AdminBffInternalClient adminBff = mock(AdminBffInternalClient.class);

        client(adminBff, false).post().uri("/bff/register")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"email\":\"   \"}")
                .exchange().expectStatus().isBadRequest();

        verify(adminBff, never()).allowlistCheck(anyString(), anyString());
    }

    @Test
    void me_withCookie_resolvesAccountBySessionToken() {
        // The cookie value is the opaque SESSION token, NOT an account id — /bff/me must
        // resolve it via getAccountBySession (introspect → account view), never
        // getAccount(sessionToken) (which 404's: a bff_ token is not an account primary key).
        AdminBffInternalClient adminBff = mock(AdminBffInternalClient.class);
        when(adminBff.getAccountBySession("bff_opaque")).thenReturn(Mono.just(ACCOUNT));

        client(adminBff, true).get().uri("/bff/me")
                .cookie(SessionCookieWebFilter.SESSION_COOKIE, "bff_opaque")
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.id").isEqualTo("acc-1")
                .jsonPath("$.handle").isEqualTo("alice@example.test");

        verify(adminBff).getAccountBySession("bff_opaque");
        verify(adminBff, never()).getAccount("bff_opaque");
    }

    @Test
    void me_noCookie_is401() {
        AdminBffInternalClient adminBff = mock(AdminBffInternalClient.class);
        client(adminBff, true).get().uri("/bff/me")
                .exchange()
                .expectStatus().isUnauthorized();
    }

    @Test
    void sessionGet_withCookie_returnsSameViewAsMe() {
        // login-ui's SessionService hydrates from GET /bff/session (permitAll, cookie-only)
        // after login — it must return the same account/session view as /bff/me.
        AdminBffInternalClient adminBff = mock(AdminBffInternalClient.class);
        when(adminBff.getAccountBySession("bff_opaque")).thenReturn(Mono.just(ACCOUNT));

        client(adminBff, true).get().uri("/bff/session")
                .cookie(SessionCookieWebFilter.SESSION_COOKIE, "bff_opaque")
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.id").isEqualTo("acc-1")
                .jsonPath("$.handle").isEqualTo("alice@example.test")
                .jsonPath("$.registrationComplete").isEqualTo(false)
                .jsonPath("$.roles").isArray();

        verify(adminBff).getAccountBySession("bff_opaque");
    }

    @Test
    void sessionGet_noCookie_is401() {
        AdminBffInternalClient adminBff = mock(AdminBffInternalClient.class);
        client(adminBff, true).get().uri("/bff/session")
                .exchange()
                .expectStatus().isUnauthorized();
    }

    @Test
    void session_delete_revokesAndExpiresCookie() {
        AdminBffInternalClient adminBff = mock(AdminBffInternalClient.class);
        when(adminBff.deleteSession("bff_opaque")).thenReturn(Mono.empty());

        client(adminBff, true).delete().uri("/bff/session")
                .cookie(SessionCookieWebFilter.SESSION_COOKIE, "bff_opaque")
                .exchange()
                .expectStatus().isNoContent()
                .expectHeader().value("Set-Cookie", v -> org.assertj.core.api.Assertions.assertThat(v).contains("bff_"));

        verify(adminBff).deleteSession("bff_opaque");
    }

    /**
     * hugmesh-generator#549's "Done when": the server is modeled STATEFULLY, not just
     * "the endpoint was called". {@code adminBff} tracks revocation in a real flag —
     * {@code getAccountBySession} answers the live account until {@code deleteSession} flips
     * it, exactly like the real admin-bff would once the row is gone. A test that only
     * verified {@code deleteSession} was invoked would pass the broken admin-bff sessionOut
     * too (it also returns 200 having deleted nothing); this one cannot, because it re-reads
     * the session afterwards and the mock's own state has to have actually changed.
     */
    @Test
    void sessionOutPost_legacyAlias_endsSessionStatefully_andExpiresCookie() {
        AdminBffInternalClient adminBff = mock(AdminBffInternalClient.class);
        AtomicBoolean revoked = new AtomicBoolean(false);
        when(adminBff.getAccountBySession("bff_opaque")).thenAnswer(inv -> revoked.get()
                ? Mono.error(new ResponseStatusException(HttpStatus.UNAUTHORIZED, "unknown or expired session"))
                : Mono.just(ACCOUNT));
        when(adminBff.deleteSession("bff_opaque")).thenAnswer(inv -> {
            revoked.set(true);
            return Mono.empty();
        });

        WebTestClient client = client(adminBff, true);

        // 1. While the session is alive, GET /bff/session (the shell's hydrate call) is 200.
        client.get().uri("/bff/session")
                .cookie(SessionCookieWebFilter.SESSION_COOKIE, "bff_opaque")
                .exchange()
                .expectStatus().isOk();

        // 2. Sign out via the LEGACY POST path (the one host-shell/login-ui actually call —
        //    hugmesh-generator#549's route-table fix now sends it here instead of admin-bff).
        client.post().uri("/bff/sessionOut")
                .cookie(SessionCookieWebFilter.SESSION_COOKIE, "bff_opaque")
                .exchange()
                .expectStatus().isNoContent()
                .expectHeader().value("Set-Cookie", v -> assertThat(v).contains("Max-Age=0"));

        // 3. Post-logout state, not the call: the SAME session token now 401s.
        client.get().uri("/bff/session")
                .cookie(SessionCookieWebFilter.SESSION_COOKIE, "bff_opaque")
                .exchange()
                .expectStatus().isUnauthorized();

        verify(adminBff).deleteSession("bff_opaque");
    }
}
