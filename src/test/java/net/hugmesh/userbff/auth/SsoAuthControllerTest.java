package net.hugmesh.userbff.auth;

import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;
import net.hugmesh.authcore.config.SessionCookieService;
import net.hugmesh.authcore.config.SessionCookieWebFilter;

import java.time.Duration;
import java.util.List;

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
                        "https://hugmesh.systems/login/callback")).build();
    }

    @Test
    void register_delegatesAllowlistEnsureAndSession() {
        AdminBffInternalClient adminBff = mock(AdminBffInternalClient.class);
        when(adminBff.allowlistCheck(eq("email"), eq("alice@example.test"))).thenReturn(Mono.just(true));
        when(adminBff.ensureAccount(eq("email"), eq("alice@example.test"))).thenReturn(Mono.just(ACCOUNT));
        when(adminBff.createSession("acc-1")).thenReturn(Mono.just(SESSION));

        client(adminBff, false).post().uri("/bff/register")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"email\":\"alice@example.test\",\"displayName\":\"Alice\",\"screenReaderName\":\"Alice\"}")
                .exchange()
                .expectStatus().isOk()
                .expectBody().jsonPath("$.token").isEqualTo("bff_opaque");

        verify(adminBff).allowlistCheck("email", "alice@example.test");
        verify(adminBff).ensureAccount("email", "alice@example.test");
    }

    /**
     * /register (permitAll, account-provisioning) MUST gate on the BFF-side allowlist. An
     * unlisted email is rejected with 403 BEFORE any account is provisioned.
     */
    @Test
    void register_notAllowlisted_is403_andNeverProvisions() {
        AdminBffInternalClient adminBff = mock(AdminBffInternalClient.class);
        when(adminBff.allowlistCheck(eq("email"), eq("blocked@example.test"))).thenReturn(Mono.just(false));

        client(adminBff, false).post().uri("/bff/register")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"email\":\"blocked@example.test\",\"displayName\":\"Mallory\",\"screenReaderName\":\"Mallory\"}")
                .exchange()
                .expectStatus().isForbidden();

        verify(adminBff).allowlistCheck("email", "blocked@example.test");
        verify(adminBff, never()).ensureAccount(anyString(), anyString());
        verify(adminBff, never()).createSession(anyString());
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
}
