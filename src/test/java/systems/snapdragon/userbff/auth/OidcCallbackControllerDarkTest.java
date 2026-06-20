package systems.snapdragon.userbff.auth;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.HttpStatus;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;
import systems.snapdragon.authcore.casdoor.BffCustodyCipher;
import systems.snapdragon.authcore.casdoor.OidcExchangeClient;
import systems.snapdragon.authcore.casdoor.OidcTokens;
import systems.snapdragon.authcore.config.SessionCookieService;

import java.time.Duration;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * {@link OidcCallbackController} ships-dark + happy-path behaviour, exercised through a
 * {@link WebTestClient#bindToController bound} controller (no full context). Proves:
 * <ul>
 *   <li><b>dark (no OidcExchangeClient bean):</b> the callback 503s, performs NO token
 *       exchange and NO internal account/session call, and sets NO cookie;</li>
 *   <li><b>enabled + stubbed clients:</b> the state is validated (single-use store),
 *       {@code exchangeCode} is called, the session is minted, custody is stamped, a 302
 *       to the UI is returned, the {@code bff_} cookie is minted ONLY when
 *       {@code app.session.cookie.enabled}, and the OIDC token values NEVER appear in the
 *       response;</li>
 *   <li><b>unknown state ⇒ 400</b> (fail closed), no exchange.</li>
 * </ul>
 */
class OidcCallbackControllerDarkTest {

    private static final String REDIRECT = "https://snapdragon.systems/login/callback";

    /** A 32-byte base64 key so BffCustodyCipher.isAvailable() is true. */
    private static BffCustodyCipher availableCipher() {
        return new BffCustodyCipher(Base64.getEncoder().encodeToString(new byte[32]));
    }

    /** An ObjectProvider yielding {@code value} from getIfAvailable() (what the
     *  controller calls); pass null for the dark (no-bean) case. */
    private static <T> ObjectProvider<T> provider(T value) {
        return new ObjectProvider<>() {
            @Override public T getObject() { return value; }
            @Override public T getObject(Object... args) { return value; }
            @Override public T getIfAvailable() { return value; }
            @Override public T getIfUnique() { return value; }
        };
    }

    @Test
    void flagOff_noExchangeClientBean_is503_andNoSideEffects() {
        OidcPendingStore pending = new OidcPendingStore(Duration.ofMinutes(5));
        pending.put("state-1", "verifier", "nonce", REDIRECT);
        AdminBffInternalClient adminBff = mock(AdminBffInternalClient.class);
        SessionCookieService cookies = new SessionCookieService(false, true, Duration.ofHours(12));

        OidcCallbackController controller = new OidcCallbackController(
                provider(null), pending, adminBff, availableCipher(), cookies, REDIRECT);
        WebTestClient client = WebTestClient.bindToController(controller).build();

        client.get().uri("/bff/auth/callback?code=abc&state=state-1")
                .exchange()
                .expectStatus().isEqualTo(HttpStatus.SERVICE_UNAVAILABLE)
                .expectHeader().doesNotExist("Set-Cookie");

        // No exchange and no account/session/custody call happened — fail closed.
        verifyNoInteractions(adminBff);
        // The state was NOT consumed (a later real callback could still use it).
        assertThat(pending.consume("state-1")).isPresent();
    }

    @Test
    void flagOn_cookieDisabled_exchangesAndRedirects_noCookie_noTokenInBody() {
        OidcPendingStore pending = new OidcPendingStore(Duration.ofMinutes(5));
        pending.put("state-1", "verifier", "nonce", REDIRECT);

        OidcExchangeClient exchange = mock(OidcExchangeClient.class);
        when(exchange.exchangeCode(eq("abc"), eq("verifier"), eq(REDIRECT)))
                .thenReturn(Mono.just(new OidcTokens("ACCESS-SECRET", "REFRESH-SECRET", "id-token-sub", 3600L)));

        AdminBffInternalClient adminBff = mock(AdminBffInternalClient.class);
        when(adminBff.ensureAccount(eq("casdoor"), anyString()))
                .thenReturn(Mono.just(new AdminBffInternalClient.AccountView(
                        "acc-1", "casdoor", "alice", false, java.util.List.of("user"))));
        when(adminBff.createSession("acc-1"))
                .thenReturn(Mono.just(new AdminBffInternalClient.SessionView("bff_opaque", "acc-1")));
        when(adminBff.stampCustody(eq("bff_opaque"), anyString(), anyString(), anyLong()))
                .thenReturn(Mono.empty());

        SessionCookieService cookies = new SessionCookieService(false, true, Duration.ofHours(12));

        OidcCallbackController controller = new OidcCallbackController(
                provider(exchange), pending, adminBff, availableCipher(), cookies, REDIRECT);
        WebTestClient client = WebTestClient.bindToController(controller).build();

        client.get().uri("/bff/auth/callback?code=abc&state=state-1")
                .exchange()
                .expectStatus().isFound()
                .expectHeader().valueEquals("Location", REDIRECT)
                // cookie disabled ⇒ no Set-Cookie (token-in-body parity)
                .expectHeader().doesNotExist("Set-Cookie")
                // a 302 has no body, but assert the OIDC token values never leak anyway
                .expectBody(String.class).consumeWith(r -> {
                    String body = r.getResponseBody();
                    assertThat(body == null ? "" : body)
                            .doesNotContain("ACCESS-SECRET")
                            .doesNotContain("REFRESH-SECRET");
                });

        verify(exchange).exchangeCode("abc", "verifier", REDIRECT);
        verify(adminBff).createSession("acc-1");
        verify(adminBff).stampCustody(eq("bff_opaque"), anyString(), anyString(), eq(3600L));
    }

    @Test
    void flagOn_cookieEnabled_mintsBffCookie() {
        OidcPendingStore pending = new OidcPendingStore(Duration.ofMinutes(5));
        pending.put("state-1", "verifier", "nonce", REDIRECT);

        OidcExchangeClient exchange = mock(OidcExchangeClient.class);
        when(exchange.exchangeCode(anyString(), anyString(), anyString()))
                .thenReturn(Mono.just(new OidcTokens("A", "R", "id-token-sub", 3600L)));
        AdminBffInternalClient adminBff = mock(AdminBffInternalClient.class);
        when(adminBff.ensureAccount(anyString(), anyString()))
                .thenReturn(Mono.just(new AdminBffInternalClient.AccountView(
                        "acc-1", "casdoor", "alice", false, java.util.List.of("user"))));
        when(adminBff.createSession("acc-1"))
                .thenReturn(Mono.just(new AdminBffInternalClient.SessionView("bff_opaque", "acc-1")));
        when(adminBff.stampCustody(anyString(), anyString(), anyString(), anyLong()))
                .thenReturn(Mono.empty());

        SessionCookieService cookies = new SessionCookieService(true, true, Duration.ofHours(12));

        OidcCallbackController controller = new OidcCallbackController(
                provider(exchange), pending, adminBff, availableCipher(), cookies, REDIRECT);
        WebTestClient client = WebTestClient.bindToController(controller).build();

        client.get().uri("/bff/auth/callback?code=abc&state=state-1")
                .exchange()
                .expectStatus().isFound()
                .expectHeader().value("Set-Cookie", v -> assertThat(v).contains("bff_"));
    }

    @Test
    void unknownState_is400_noExchange() {
        OidcPendingStore pending = new OidcPendingStore(Duration.ofMinutes(5));
        OidcExchangeClient exchange = mock(OidcExchangeClient.class);
        AdminBffInternalClient adminBff = mock(AdminBffInternalClient.class);
        SessionCookieService cookies = new SessionCookieService(false, true, Duration.ofHours(12));

        OidcCallbackController controller = new OidcCallbackController(
                provider(exchange), pending, adminBff, availableCipher(), cookies, REDIRECT);
        WebTestClient client = WebTestClient.bindToController(controller).build();

        client.get().uri("/bff/auth/callback?code=abc&state=never-seen")
                .exchange()
                .expectStatus().isBadRequest();

        verify(exchange, never()).exchangeCode(anyString(), anyString(), any());
        verifyNoInteractions(adminBff);
    }

    @Test
    void custodyKeyBlank_is503_evenWhenExchangeClientPresent() {
        OidcPendingStore pending = new OidcPendingStore(Duration.ofMinutes(5));
        pending.put("state-1", "verifier", "nonce", REDIRECT);
        OidcExchangeClient exchange = mock(OidcExchangeClient.class);
        AdminBffInternalClient adminBff = mock(AdminBffInternalClient.class);
        BffCustodyCipher inert = new BffCustodyCipher("");   // blank key ⇒ not available
        SessionCookieService cookies = new SessionCookieService(false, true, Duration.ofHours(12));

        OidcCallbackController controller = new OidcCallbackController(
                provider(exchange), pending, adminBff, inert, cookies, REDIRECT);
        WebTestClient client = WebTestClient.bindToController(controller).build();

        client.get().uri("/bff/auth/callback?code=abc&state=state-1")
                .exchange()
                .expectStatus().isEqualTo(HttpStatus.SERVICE_UNAVAILABLE);

        verifyNoInteractions(adminBff);
    }
}
