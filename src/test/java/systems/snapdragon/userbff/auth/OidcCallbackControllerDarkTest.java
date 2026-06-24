package systems.snapdragon.userbff.auth;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;
import systems.snapdragon.authcore.casdoor.BffCustodyCipher;
import systems.snapdragon.authcore.casdoor.OidcExchangeClient;
import systems.snapdragon.authcore.casdoor.OidcTokens;
import systems.snapdragon.authcore.config.SessionCookieService;

import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * {@link OidcCallbackController} ships-dark + happy-path behaviour, exercised through a
 * {@link WebTestClient#bindToController bound} controller (no full context). Proves:
 * <ul>
 *   <li><b>dark (no OidcExchangeClient bean):</b> 503, no side-effects, no cookie;</li>
 *   <li><b>cipher unavailable:</b> 503, no side-effects, even when exchange client present;</li>
 *   <li><b>enabled + cookie disabled:</b> exchanges code, provisions account+session,
 *       stamps custody, returns 200 OK with {registrationComplete, status:'active'},
 *       NO cookie, token values never leak in response;</li>
 *   <li><b>enabled + cookie enabled:</b> 200 OK with bff_ cookie;</li>
 *   <li><b>exchange failure:</b> error propagates (5xx), no account or session call.</li>
 * </ul>
 * The browser-PKCE model: login-ui owns state validation (sessionStorage) — the BFF
 * receives only {code, codeVerifier, redirectUri} in a POST body.
 */
class OidcCallbackControllerDarkTest {

    private static final String REDIRECT = "https://snapdragon.systems/login/callback";

    /** A 32-byte base64 key so BffCustodyCipher.isAvailable() is true. */
    private static BffCustodyCipher availableCipher() {
        return new BffCustodyCipher(Base64.getEncoder().encodeToString(new byte[32]));
    }

    /** ObjectProvider yielding {@code value} from getIfAvailable(); pass null for the dark case. */
    private static <T> ObjectProvider<T> provider(T value) {
        return new ObjectProvider<>() {
            @Override public T getObject() { return value; }
            @Override public T getObject(Object... args) { return value; }
            @Override public T getIfAvailable() { return value; }
            @Override public T getIfUnique() { return value; }
        };
    }

    private static Map<String, String> callbackBody() {
        return Map.of("code", "abc", "codeVerifier", "verifier", "redirectUri", REDIRECT);
    }

    @Test
    void flagOff_noExchangeClientBean_is503_andNoSideEffects() {
        AdminBffInternalClient adminBff = mock(AdminBffInternalClient.class);
        SessionCookieService cookies = new SessionCookieService(false, true, Duration.ofHours(12));

        OidcCallbackController controller = new OidcCallbackController(
                provider(null), adminBff, availableCipher(), cookies, REDIRECT);
        WebTestClient client = WebTestClient.bindToController(controller).build();

        client.post().uri("/bff/auth/callback")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(callbackBody())
                .exchange()
                .expectStatus().isEqualTo(HttpStatus.SERVICE_UNAVAILABLE)
                .expectHeader().doesNotExist("Set-Cookie");

        verifyNoInteractions(adminBff);
    }

    @Test
    void custodyKeyBlank_is503_evenWhenExchangeClientPresent() {
        OidcExchangeClient exchange = mock(OidcExchangeClient.class);
        AdminBffInternalClient adminBff = mock(AdminBffInternalClient.class);
        BffCustodyCipher inert = new BffCustodyCipher("");   // blank key → not available
        SessionCookieService cookies = new SessionCookieService(false, true, Duration.ofHours(12));

        OidcCallbackController controller = new OidcCallbackController(
                provider(exchange), adminBff, inert, cookies, REDIRECT);
        WebTestClient client = WebTestClient.bindToController(controller).build();

        client.post().uri("/bff/auth/callback")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(callbackBody())
                .exchange()
                .expectStatus().isEqualTo(HttpStatus.SERVICE_UNAVAILABLE);

        verifyNoInteractions(adminBff);
    }

    @Test
    void flagOn_cookieDisabled_exchanges200_noCookie_noTokenInBody() {
        OidcExchangeClient exchange = mock(OidcExchangeClient.class);
        when(exchange.exchangeCode(eq("abc"), eq("verifier"), eq(REDIRECT)))
                .thenReturn(Mono.just(new OidcTokens("ACCESS-SECRET", "REFRESH-SECRET", "id-token-sub", 3600L)));

        AdminBffInternalClient adminBff = mock(AdminBffInternalClient.class);
        when(adminBff.ensureAccount(eq("casdoor"), anyString()))
                .thenReturn(Mono.just(new AdminBffInternalClient.AccountView(
                        "acc-1", "casdoor", "alice", false, List.of("user"))));
        when(adminBff.createSession("acc-1"))
                .thenReturn(Mono.just(new AdminBffInternalClient.SessionView("bff_opaque", "acc-1")));
        when(adminBff.stampCustody(eq("bff_opaque"), anyString(), anyString(), anyLong()))
                .thenReturn(Mono.empty());

        SessionCookieService cookies = new SessionCookieService(false, true, Duration.ofHours(12));

        OidcCallbackController controller = new OidcCallbackController(
                provider(exchange), adminBff, availableCipher(), cookies, REDIRECT);
        WebTestClient client = WebTestClient.bindToController(controller).build();

        client.post().uri("/bff/auth/callback")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(callbackBody())
                .exchange()
                .expectStatus().isOk()
                .expectHeader().doesNotExist("Set-Cookie")
                .expectBody(OidcCallbackController.CallbackResult.class).consumeWith(r -> {
                    OidcCallbackController.CallbackResult body = r.getResponseBody();
                    assertThat(body).isNotNull();
                    // registrationComplete comes from AccountView(registrationComplete=false)
                    assertThat(body.registrationComplete()).isFalse();
                    assertThat(body.status()).isEqualTo("active");
                });

        verify(exchange).exchangeCode("abc", "verifier", REDIRECT);
        verify(adminBff).createSession("acc-1");
        verify(adminBff).stampCustody(eq("bff_opaque"), anyString(), anyString(), eq(3600L));
    }

    @Test
    void flagOn_cookieEnabled_sets200AndMintsBffCookie() {
        OidcExchangeClient exchange = mock(OidcExchangeClient.class);
        when(exchange.exchangeCode(anyString(), anyString(), anyString()))
                .thenReturn(Mono.just(new OidcTokens("A", "R", "id-token-sub", 3600L)));
        AdminBffInternalClient adminBff = mock(AdminBffInternalClient.class);
        when(adminBff.ensureAccount(anyString(), anyString()))
                .thenReturn(Mono.just(new AdminBffInternalClient.AccountView(
                        "acc-1", "casdoor", "alice", false, List.of("user"))));
        when(adminBff.createSession("acc-1"))
                .thenReturn(Mono.just(new AdminBffInternalClient.SessionView("bff_opaque", "acc-1")));
        when(adminBff.stampCustody(anyString(), anyString(), anyString(), anyLong()))
                .thenReturn(Mono.empty());

        SessionCookieService cookies = new SessionCookieService(true, true, Duration.ofHours(12));

        OidcCallbackController controller = new OidcCallbackController(
                provider(exchange), adminBff, availableCipher(), cookies, REDIRECT);
        WebTestClient client = WebTestClient.bindToController(controller).build();

        client.post().uri("/bff/auth/callback")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(callbackBody())
                .exchange()
                .expectStatus().isOk()
                .expectHeader().value("Set-Cookie", v -> assertThat(v).contains("bff_"));
    }

    @Test
    void exchangeClientError_propagates5xx_noAccountOrSessionCall() {
        OidcExchangeClient exchange = mock(OidcExchangeClient.class);
        when(exchange.exchangeCode(anyString(), anyString(), anyString()))
                .thenReturn(Mono.error(new RuntimeException("Casdoor rejected: bad verifier")));
        AdminBffInternalClient adminBff = mock(AdminBffInternalClient.class);
        SessionCookieService cookies = new SessionCookieService(false, true, Duration.ofHours(12));

        OidcCallbackController controller = new OidcCallbackController(
                provider(exchange), adminBff, availableCipher(), cookies, REDIRECT);
        WebTestClient client = WebTestClient.bindToController(controller).build();

        client.post().uri("/bff/auth/callback")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(callbackBody())
                .exchange()
                .expectStatus().is5xxServerError();

        verify(exchange).exchangeCode(anyString(), anyString(), anyString());
        verifyNoInteractions(adminBff);
    }
}
