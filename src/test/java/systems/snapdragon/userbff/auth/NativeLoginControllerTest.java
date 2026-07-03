package systems.snapdragon.userbff.auth;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.MediaType;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;
import systems.snapdragon.authcore.casdoor.BffCustodyCipher;
import systems.snapdragon.authcore.casdoor.OidcExchangeClient;
import systems.snapdragon.authcore.casdoor.OidcTokens;
import systems.snapdragon.authcore.config.SessionCookieService;
import systems.snapdragon.userbff.auth.CasdoorLoginClient.CasdoorLoginResult;

import java.time.Duration;
import java.util.Base64;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.nullable;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * NATIVE LOGIN — {@code POST /bff/login}. The browser posts only {@code {username,password}};
 * a MOCKED {@link CasdoorLoginClient} stands in for the server-side Casdoor {@code /api/login}
 * credential check, and the real {@link OidcLoginCompletionService} runs over a MOCKED
 * {@link OidcExchangeClient} + {@link AdminBffInternalClient} (the exchange→provision→custody→
 * cookie path). Proves:
 * <ul>
 *   <li><b>happy path:</b> code → exchange → session; 200 with the bff_ cookie and
 *       {registrationComplete,status:'active',mfaRequired:false}, and NO token/JWT/Casdoor-URL
 *       anywhere in the response body;</li>
 *   <li><b>bad creds:</b> 401 {error:'invalid_credentials',message:..}, NO cookie, NO exchange;</li>
 *   <li><b>MFA required:</b> 200 {mfaRequired:true,mfaType:[..]}, NO cookie, NO session minted.</li>
 * </ul>
 */
class NativeLoginControllerTest {

    private static final String REDIRECT = "https://snapdragon.systems/login/callback";
    private static final String LOGIN_BASE = "http://casdoor.snapdragon-pki.svc.cluster.local:8000";

    /** A 32-byte base64 key so BffCustodyCipher.isAvailable() is true. */
    private static BffCustodyCipher availableCipher() {
        return new BffCustodyCipher(Base64.getEncoder().encodeToString(new byte[32]));
    }

    /** ObjectProvider yielding {@code value} from getIfAvailable(); pass null for the dark case. */
    static <T> ObjectProvider<T> provider(T value) {
        return new ObjectProvider<>() {
            @Override public T getObject() { return value; }
            @Override public T getObject(Object... args) { return value; }
            @Override public T getIfAvailable() { return value; }
            @Override public T getIfUnique() { return value; }
        };
    }

    private WebTestClient client(CasdoorLoginClient casdoorLogin,
                                 OidcExchangeClient exchange,
                                 AdminBffInternalClient adminBff,
                                 boolean cookieEnabled) {
        SessionCookieService cookies = new SessionCookieService(cookieEnabled, true, Duration.ofHours(12));
        OidcLoginCompletionService completion =
                new OidcLoginCompletionService(provider(exchange), adminBff, availableCipher(), cookies);
        return WebTestClient.bindToController(
                new SsoAuthController(casdoorLogin, completion, adminBff, cookies, REDIRECT)).build();
    }

    @Test
    void happyPath_setsBffCookie_returnsFlags_noTokenInBody() {
        CasdoorLoginClient casdoorLogin = mock(CasdoorLoginClient.class);
        when(casdoorLogin.login(eq("alice"), eq("s3cret"), anyString(), anyString(), eq(REDIRECT),
                nullable(String.class), nullable(String.class)))
                .thenReturn(Mono.just(CasdoorLoginResult.code("auth-code-xyz")));

        OidcExchangeClient exchange = mock(OidcExchangeClient.class);
        when(exchange.exchangeCode(eq("auth-code-xyz"), anyString(), eq(REDIRECT)))
                .thenReturn(Mono.just(new OidcTokens(
                        "ACCESS-JWT-SECRET", "REFRESH-SECRET", "ID-TOKEN-SUB", 3600L)));

        AdminBffInternalClient adminBff = mock(AdminBffInternalClient.class);
        when(adminBff.ensureAccount(eq("casdoor"), anyString()))
                .thenReturn(Mono.just(new AdminBffInternalClient.AccountView(
                        "acc-1", "casdoor", "alice", true, List.of("user"))));
        when(adminBff.createSession("acc-1"))
                .thenReturn(Mono.just(new AdminBffInternalClient.SessionView("bff_opaque_session", "acc-1")));
        when(adminBff.stampCustody(eq("bff_opaque_session"), anyString(), anyString(), anyLong()))
                .thenReturn(Mono.empty());

        client(casdoorLogin, exchange, adminBff, true).post().uri("/bff/login")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"username\":\"alice\",\"password\":\"s3cret\"}")
                .exchange()
                .expectStatus().isOk()
                .expectHeader().value("Set-Cookie", v -> assertThat(v).contains("bff_"))
                .expectBody(String.class).consumeWith(r -> {
                    String body = r.getResponseBody();
                    assertThat(body).isNotNull();
                    // Non-secret routing flags present.
                    assertThat(body).contains("\"registrationComplete\":true");
                    assertThat(body).contains("\"status\":\"active\"");
                    assertThat(body).contains("\"mfaRequired\":false");
                    // INVARIANT: no token/JWT/verifier/state/Casdoor-URL/opaque-session leaks in the body.
                    assertThat(body)
                            .doesNotContain("ACCESS-JWT-SECRET")
                            .doesNotContain("REFRESH-SECRET")
                            .doesNotContain("ID-TOKEN-SUB")
                            .doesNotContain("auth-code-xyz")
                            .doesNotContain("bff_opaque_session")
                            .doesNotContain("code_verifier")
                            .doesNotContain("codeVerifier")
                            .doesNotContain("casdoor")
                            .doesNotContain(LOGIN_BASE)
                            .doesNotContain("access_token")
                            .doesNotContain("id_token");
                });

        verify(exchange).exchangeCode(eq("auth-code-xyz"), anyString(), eq(REDIRECT));
        verify(adminBff).createSession("acc-1");
        verify(adminBff).stampCustody(eq("bff_opaque_session"), anyString(), anyString(), eq(3600L));
    }

    @Test
    void badCredentials_is401_invalidCredentials_noCookie_noExchange() {
        CasdoorLoginClient casdoorLogin = mock(CasdoorLoginClient.class);
        when(casdoorLogin.login(anyString(), anyString(), anyString(), anyString(), anyString(),
                nullable(String.class), nullable(String.class)))
                .thenReturn(Mono.just(CasdoorLoginResult.error("password is incorrect")));

        OidcExchangeClient exchange = mock(OidcExchangeClient.class);
        AdminBffInternalClient adminBff = mock(AdminBffInternalClient.class);

        client(casdoorLogin, exchange, adminBff, true).post().uri("/bff/login")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"username\":\"alice\",\"password\":\"wrong\"}")
                .exchange()
                .expectStatus().isUnauthorized()
                .expectHeader().doesNotExist("Set-Cookie")
                .expectBody()
                .jsonPath("$.error").isEqualTo("invalid_credentials")
                .jsonPath("$.message").isEqualTo("password is incorrect");

        verifyNoInteractions(exchange);
        verifyNoInteractions(adminBff);
    }

    @Test
    void mfaRequired_is200_mfaChallenge_noCookie_noSession() {
        CasdoorLoginClient casdoorLogin = mock(CasdoorLoginClient.class);
        when(casdoorLogin.login(anyString(), anyString(), anyString(), anyString(), anyString(),
                nullable(String.class), nullable(String.class)))
                .thenReturn(Mono.just(CasdoorLoginResult.mfaRequired(List.of("totp"))));

        OidcExchangeClient exchange = mock(OidcExchangeClient.class);
        AdminBffInternalClient adminBff = mock(AdminBffInternalClient.class);

        client(casdoorLogin, exchange, adminBff, true).post().uri("/bff/login")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"username\":\"alice\",\"password\":\"s3cret\"}")
                .exchange()
                .expectStatus().isOk()
                .expectHeader().doesNotExist("Set-Cookie")
                .expectBody()
                .jsonPath("$.mfaRequired").isEqualTo(true)
                .jsonPath("$.mfaType[0]").isEqualTo("totp");

        verifyNoInteractions(exchange);
        verifyNoInteractions(adminBff);
    }

    @Test
    void secondFactorPasscode_forwardedToCasdoor() {
        CasdoorLoginClient casdoorLogin = mock(CasdoorLoginClient.class);
        when(casdoorLogin.login(eq("alice"), eq("s3cret"), anyString(), anyString(), eq(REDIRECT),
                eq("123456"), eq("totp")))
                .thenReturn(Mono.just(CasdoorLoginResult.code("auth-code-mfa")));

        OidcExchangeClient exchange = mock(OidcExchangeClient.class);
        when(exchange.exchangeCode(eq("auth-code-mfa"), anyString(), eq(REDIRECT)))
                .thenReturn(Mono.just(new OidcTokens("A", "R", "ID", 3600L)));
        AdminBffInternalClient adminBff = mock(AdminBffInternalClient.class);
        when(adminBff.ensureAccount(eq("casdoor"), anyString()))
                .thenReturn(Mono.just(new AdminBffInternalClient.AccountView(
                        "acc-1", "casdoor", "alice", true, List.of("user"))));
        when(adminBff.createSession("acc-1"))
                .thenReturn(Mono.just(new AdminBffInternalClient.SessionView("bff_opaque", "acc-1")));
        when(adminBff.stampCustody(anyString(), anyString(), anyString(), anyLong()))
                .thenReturn(Mono.empty());

        client(casdoorLogin, exchange, adminBff, true).post().uri("/bff/login")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"username\":\"alice\",\"password\":\"s3cret\",\"mfaPasscode\":\"123456\",\"mfaType\":\"totp\"}")
                .exchange()
                .expectStatus().isOk();

        verify(casdoorLogin).login(eq("alice"), eq("s3cret"), anyString(), anyString(), eq(REDIRECT),
                eq("123456"), eq("totp"));
    }
}
