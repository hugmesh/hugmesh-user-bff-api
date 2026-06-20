package systems.snapdragon.userbff.auth;

import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;
import systems.snapdragon.authcore.config.SessionCookieService;
import systems.snapdragon.authcore.config.SessionCookieWebFilter;

import java.time.Duration;
import java.util.List;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * {@link SsoAuthController} delegates every account/session op to a MOCKED
 * {@link AdminBffInternalClient} — there is NO local auth-core AccountStore /
 * BffSessionRepository bean (user-bff has no account/session DB). Bound via
 * {@link WebTestClient#bindToController} (no full context). Proves the delegation
 * shapes for /login, /register, /me, /session and the cookie-ships-dark posture.
 */
class SsoAuthControllerTest {

    private static final AdminBffInternalClient.AccountView ACCOUNT =
            new AdminBffInternalClient.AccountView("acc-1", "email", "alice@example.test", false, List.of("user"));
    private static final AdminBffInternalClient.SessionView SESSION =
            new AdminBffInternalClient.SessionView("bff_opaque", "acc-1");

    private WebTestClient client(AdminBffInternalClient adminBff, boolean cookieEnabled) {
        SessionCookieService cookies = new SessionCookieService(cookieEnabled, true, Duration.ofHours(12));
        return WebTestClient.bindToController(new SsoAuthController(adminBff, cookies)).build();
    }

    @Test
    void login_delegatesAllowlistEnsureAndSession_tokenInBody() {
        AdminBffInternalClient adminBff = mock(AdminBffInternalClient.class);
        when(adminBff.allowlistCheck(eq("email"), anyString())).thenReturn(Mono.just(true));
        when(adminBff.ensureAccount(eq("email"), anyString())).thenReturn(Mono.just(ACCOUNT));
        when(adminBff.createSession("acc-1")).thenReturn(Mono.just(SESSION));

        client(adminBff, false).post().uri("/bff/login")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"provider\":\"email\",\"email\":\"alice@example.test\",\"username\":null}")
                .exchange()
                .expectStatus().isOk()
                // cookie disabled ⇒ token in body, no Set-Cookie (parity with today)
                .expectHeader().doesNotExist("Set-Cookie")
                .expectBody()
                .jsonPath("$.token").isEqualTo("bff_opaque")
                .jsonPath("$.id").isEqualTo("acc-1");

        verify(adminBff).ensureAccount("email", "alice@example.test");
        verify(adminBff).createSession("acc-1");
    }

    @Test
    void login_notAllowlisted_is403() {
        AdminBffInternalClient adminBff = mock(AdminBffInternalClient.class);
        when(adminBff.allowlistCheck(anyString(), anyString())).thenReturn(Mono.just(false));

        client(adminBff, false).post().uri("/bff/login")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"provider\":\"email\",\"email\":\"blocked@example.test\",\"username\":null}")
                .exchange()
                .expectStatus().isForbidden();
    }

    @Test
    void login_cookieEnabled_setsBffCookie() {
        AdminBffInternalClient adminBff = mock(AdminBffInternalClient.class);
        when(adminBff.allowlistCheck(anyString(), anyString())).thenReturn(Mono.just(true));
        when(adminBff.ensureAccount(anyString(), anyString())).thenReturn(Mono.just(ACCOUNT));
        when(adminBff.createSession("acc-1")).thenReturn(Mono.just(SESSION));

        client(adminBff, true).post().uri("/bff/login")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"provider\":\"email\",\"email\":\"alice@example.test\",\"username\":null}")
                .exchange()
                .expectStatus().isOk()
                .expectHeader().value("Set-Cookie", v -> org.assertj.core.api.Assertions.assertThat(v).contains("bff_"));
    }

    @Test
    void register_delegatesEnsureAccount() {
        AdminBffInternalClient adminBff = mock(AdminBffInternalClient.class);
        when(adminBff.ensureAccount(eq("email"), eq("alice@example.test"))).thenReturn(Mono.just(ACCOUNT));
        when(adminBff.createSession("acc-1")).thenReturn(Mono.just(SESSION));

        client(adminBff, false).post().uri("/bff/register")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"email\":\"alice@example.test\",\"displayName\":\"Alice\",\"screenReaderName\":\"Alice\"}")
                .exchange()
                .expectStatus().isOk()
                .expectBody().jsonPath("$.token").isEqualTo("bff_opaque");

        verify(adminBff).ensureAccount("email", "alice@example.test");
    }

    @Test
    void me_withCookie_delegatesGetAccount() {
        AdminBffInternalClient adminBff = mock(AdminBffInternalClient.class);
        when(adminBff.getAccount("bff_opaque")).thenReturn(Mono.just(ACCOUNT));

        client(adminBff, true).get().uri("/bff/me")
                .cookie(SessionCookieWebFilter.SESSION_COOKIE, "bff_opaque")
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.id").isEqualTo("acc-1")
                .jsonPath("$.handle").isEqualTo("alice@example.test");

        verify(adminBff).getAccount("bff_opaque");
    }

    @Test
    void me_noCookie_is401() {
        AdminBffInternalClient adminBff = mock(AdminBffInternalClient.class);
        client(adminBff, true).get().uri("/bff/me")
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
