package net.hugmesh.userbff.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Duration;

import net.hugmesh.authcore.casdoor.BffCustodyCipher;
import net.hugmesh.authcore.config.SessionCookieService;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;

/**
 * {@code POST /bff/login} refuses a password on a domain whose sign-in methods leave it out
 * (hugmesh-generator#1107), before Casdoor sees the credential; dark settings, a host that
 * matches no listed domain, and a domain that lists {@code password} keep today's login.
 */
class PasswordPerDomainTest {

    @Test
    void theRule() {
        OAuthSettings s = OAuthPiecesTest.settings(true,
                "shop.example=google;mesh.example=password,google");
        assertThat(s.passwordRefused("shop.example")).isTrue();
        assertThat(s.passwordRefused("login.shop.example:9080")).isTrue();
        assertThat(s.passwordRefused("mesh.example")).isFalse();
        assertThat(s.passwordRefused("other.example")).isFalse();
        assertThat(OAuthPiecesTest.settings(false, "shop.example=google")
                .passwordRefused("shop.example")).isFalse();
    }

    private WebTestClient client(CasdoorLoginClient casdoorLogin, OAuthSettings settings,
                                 String base) {
        SessionCookieService cookies = new SessionCookieService(true, true, Duration.ofHours(12));
        OidcLoginCompletionService completion = new OidcLoginCompletionService(
                NativeLoginControllerTest.provider(null), mock(AdminBffInternalClient.class),
                new BffCustodyCipher(""), cookies);
        return WebTestClient.bindToController(new SsoAuthController(casdoorLogin, completion,
                        mock(AdminBffInternalClient.class), cookies,
                        "https://hugmesh.net/login/callback", settings))
                .configureClient().baseUrl(base).build();
    }

    @Test
    void aDomainWithoutPasswordRefusesBeforeCasdoor() {
        CasdoorLoginClient casdoorLogin = mock(CasdoorLoginClient.class);
        client(casdoorLogin, OAuthPiecesTest.settings(true, "shop.example=google"),
                "https://shop.example").post().uri("/bff/login")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"username\":\"ann\",\"password\":\"pw\"}")
                .exchange().expectStatus().isForbidden()
                .expectBody().jsonPath("$.error").isEqualTo("password_disabled");
        verify(casdoorLogin, never()).login(anyString(), anyString(), anyString(), anyString(),
                anyString(), any(), any());
    }

    @Test
    void aDomainWithPasswordStillReachesCasdoor() {
        CasdoorLoginClient casdoorLogin = mock(CasdoorLoginClient.class);
        when(casdoorLogin.login(anyString(), anyString(), anyString(), anyString(), anyString(),
                any(), any())).thenReturn(Mono.just(
                        CasdoorLoginClient.CasdoorLoginResult.error("bad password")));
        client(casdoorLogin, OAuthPiecesTest.settings(true, "mesh.example=password,google"),
                "https://mesh.example").post().uri("/bff/login")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"username\":\"ann\",\"password\":\"pw\"}")
                .exchange().expectStatus().isUnauthorized();
        verify(casdoorLogin).login(anyString(), anyString(), anyString(), anyString(),
                anyString(), any(), any());
    }
}
