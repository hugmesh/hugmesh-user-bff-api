package net.hugmesh.userbff.config;

import net.hugmesh.authcore.config.SessionCookieService;
import net.hugmesh.commons.config.TenancyResolvers;
import net.hugmesh.commons.config.TenancyResourceServerConfig;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.userbff.auth.AdminBffInternalClient;
import net.hugmesh.userbff.auth.CasdoorLoginClient;
import net.hugmesh.userbff.auth.OidcLoginCompletionService;
import net.hugmesh.userbff.auth.SsoAuthController;
import net.hugmesh.userbff.testsupport.TestIssuer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.test.web.reactive.server.EntityExchangeResult;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * {@code GET /bff/session} and {@code GET /bff/me} through the REAL chain: {@link SecurityConfig},
 * {@link BffSessionAuthenticationWebFilter}, {@link SsoAuthController} and the real
 * {@link AdminBffInternalClient} over a stub admin-bff whose introspect body reports the status
 * the token name encodes.
 *
 * <p>The exploit this pins: the filter authenticates from the {@code Authorization} header first
 * and never looks at the cookie, while the view used to read the {@code bff_session} cookie and
 * drop its status. An active {@code bff_} bearer (or any valid JWT) plus a suspended, banned or
 * unknown-status cookie returned 200 with that account's id, handle and roles.
 */
class SessionViewStatusChainTest extends SecuritySliceSupport {

    private static final Map<String, String> INTROSPECT = Map.ofEntries(
            Map.entry("bff_active", "{\"id\":\"acc-1\",\"status\":\"active\",\"mfaSatisfied\":false}"),
            Map.entry("bff_activeupper", "{\"id\":\"acc-1\",\"status\":\"ACTIVE\",\"mfaSatisfied\":false}"),
            Map.entry("bff_suspended", "{\"id\":\"acc-2\",\"status\":\"suspended\",\"mfaSatisfied\":false}"),
            Map.entry("bff_banned", "{\"id\":\"acc-2\",\"status\":\"banned\",\"mfaSatisfied\":false}"),
            Map.entry("bff_omitted", "{\"id\":\"acc-2\",\"mfaSatisfied\":false}"),
            Map.entry("bff_null", "{\"id\":\"acc-2\",\"status\":null,\"mfaSatisfied\":false}"),
            Map.entry("bff_pending", "{\"id\":\"acc-2\",\"status\":\"pending\",\"mfaSatisfied\":false}"),
            Map.entry("bff_empty", "{\"id\":\"acc-2\",\"status\":\"\",\"mfaSatisfied\":false}"),
            Map.entry("bff_padded", "{\"id\":\"acc-2\",\"status\":\" active\",\"mfaSatisfied\":false}"),
            // U+0130 (dotted capital I): String.equalsIgnoreCase folds it to 'i'.
            Map.entry("bff_dotted", "{\"id\":\"acc-2\",\"status\":\"act\u0130ve\",\"mfaSatisfied\":false}"),
            Map.entry("bff_obj", "{\"id\":\"acc-2\",\"status\":{\"x\":1},\"mfaSatisfied\":false}"),
            Map.entry("bff_arr", "{\"id\":\"acc-2\",\"status\":[\"active\"],\"mfaSatisfied\":false}"),
            Map.entry("bff_dup", "{\"id\":\"acc-2\",\"status\":\"suspended\",\"status\":\"active\",\"mfaSatisfied\":false}"));

    /** acc-1 is the active caller; acc-2 is the account behind every non-active session. */
    private static String account(String id) {
        String handle = "acc-1".equals(id) ? "owner" : "victim";
        return "{\"id\":\"" + id + "\",\"provider\":\"casdoor\",\"handle\":\"" + handle + "\","
                + "\"registrationComplete\":true,\"roles\":[\"user\",\"superadmin\"]}";
    }

    private static TestIssuer issuer;
    private static TestIssuer otherIssuer;
    private static WebTestClient client;

    @BeforeAll
    static void setUp() {
        issuer = new TestIssuer();
        otherIssuer = new TestIssuer();
        DomainRegistry registry = new DomainRegistry(issuer.issuerUri(),
                issuer.issuerUri() + "=brandx," + otherIssuer.issuerUri() + "=brandy");
        TenancyResourceServerConfig tenancy = new TenancyResourceServerConfig(registry, "", "", false, 600000L);
        ReactiveAuthenticationManagerResolver<ServerWebExchange> resolver = TenancyResolvers.tenantResolver(tenancy);
        AdminBffInternalClient adminBff = new AdminBffInternalClient(
                WebClient.builder().baseUrl("http://admin-bff.test").exchangeFunction(stubAdminBff()).build());
        SsoAuthController sso = new SsoAuthController(mock(CasdoorLoginClient.class),
                mock(OidcLoginCompletionService.class), adminBff, mock(SessionCookieService.class), "https://x/cb");
        client = sliceClientWithBffSessionAuth(registry, provider(resolver), provider(adminBff), sso, new Probe());
    }

    @AfterAll
    static void tearDown() {
        issuer.close();
        otherIssuer.close();
    }

    private static ExchangeFunction stubAdminBff() {
        return request -> {
            String body;
            if (request.url().getPath().endsWith("/session/introspect")) {
                String auth = request.headers().getFirst("Authorization");
                body = auth == null ? null : INTROSPECT.get(auth.substring("Bearer ".length()));
                if (body == null) {
                    return Mono.just(ClientResponse.create(HttpStatus.UNAUTHORIZED).build());
                }
            } else {
                String path = request.url().getPath();
                body = account(path.substring(path.lastIndexOf('/') + 1));
            }
            return Mono.just(ClientResponse.create(HttpStatus.OK)
                    .header("Content-Type", "application/json").body(body).build());
        };
    }

    @RestController
    static class Probe {
        @GetMapping("/bff/user/_probe")
        Mono<String> ok() {
            return Mono.just("ok");
        }
    }

    private static EntityExchangeResult<String> get(String path, String authorization, String cookie) {
        var spec = client.get().uri(path);
        if (authorization != null) {
            spec = spec.header("Authorization", authorization);
        }
        if (cookie != null) {
            spec = spec.cookie("bff_session", cookie);
        }
        return spec.exchange().expectBody(String.class).returnResult();
    }

    private static void assertRefused(EntityExchangeResult<String> res, String expectedReason) {
        assertThat(res.getStatus().value()).as("status").isEqualTo(403);
        assertThat(res.getResponseHeaders().getFirst("X-Bff-Denied")).isEqualTo(expectedReason);
        assertThat(String.valueOf(res.getResponseBody())).doesNotContain("victim").doesNotContain("superadmin");
    }

    private static String reasonFor(String token) {
        return switch (token) {
            case "bff_suspended" -> "account-suspended";
            case "bff_banned" -> "account-banned";
            default -> "account-status-unrecognized";
        };
    }

    // ── the reported exploit: active bff_ bearer + non-active cookie ────────────────────

    @ParameterizedTest
    @ValueSource(strings = {"bff_suspended", "bff_banned", "bff_omitted", "bff_null", "bff_pending",
            "bff_empty", "bff_padded", "bff_dotted"})
    void activeBearerPlusNonActiveCookie_neverReturnsTheCookiesAccount(String cookie) {
        for (String path : List.of("/bff/session", "/bff/me")) {
            // The view describes the bearer's session (the one the filter authenticated): the
            // active caller's own account, never the non-active cookie's.
            EntityExchangeResult<String> res = get(path, "Bearer bff_active", cookie);
            assertThat(res.getStatus().value()).as(path).isEqualTo(200);
            assertThat(res.getResponseBody()).contains("\"id\":\"acc-1\"").doesNotContain("victim");
            // ...and the same cookie with no competing bearer is refused.
            assertRefused(get(path, null, cookie), reasonFor(cookie));
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"bff_suspended", "bff_banned", "bff_omitted", "bff_null", "bff_pending",
            "bff_empty", "bff_padded", "bff_dotted"})
    void nonActiveBearerPlusActiveCookie_isRefusedByTheFilter(String bearer) {
        // Reversed: the bearer wins in both the filter and the view, so a non-active bearer
        // cannot borrow an active cookie's view.
        assertRefused(get("/bff/me", "Bearer " + bearer, "bff_active"), reasonFor(bearer));
        assertRefused(get("/bff/session", "Bearer " + bearer, "bff_active"), reasonFor(bearer));
    }

    // ── a valid JWT + non-active cookie: the filter never looks at the cookie ───────────

    @ParameterizedTest
    @ValueSource(strings = {"bff_suspended", "bff_banned", "bff_omitted", "bff_null", "bff_pending",
            "bff_empty", "bff_padded", "bff_dotted"})
    void validJwtPlusNonActiveCookie_meIsRefused(String cookie) {
        String jwt = issuer.mint("someone", List.of("user"));
        assertRefused(get("/bff/me", "Bearer " + jwt, cookie), reasonFor(cookie));
        assertRefused(get("/bff/session", "Bearer " + jwt, cookie), reasonFor(cookie));
    }

    @ParameterizedTest
    @ValueSource(strings = {"bff_obj", "bff_arr", "bff_dup"})
    void malformedCookieStatus_neverYieldsAView(String cookie) {
        String jwt = issuer.mint("someone", List.of("user"));
        for (EntityExchangeResult<String> res : List.of(
                get("/bff/me", "Bearer " + jwt, cookie),
                get("/bff/session", null, cookie))) {
            assertThat(res.getStatus().is2xxSuccessful()).as("status %s", res.getStatus()).isFalse();
            assertThat(String.valueOf(res.getResponseBody())).doesNotContain("victim");
        }
    }

    // ── non-ASCII lookalike in the filter itself ───────────────────────────────────────

    @Test
    void dottedCapitalIStatus_doesNotAuthenticate() {
        assertRefused(get("/bff/user/_probe", "Bearer bff_dotted", null), "account-status-unrecognized");
        assertRefused(get("/bff/user/_probe", null, "bff_dotted"), "account-status-unrecognized");
    }

    // ── controls: active sessions still work ────────────────────────────────────────────

    @Test
    void activeSessions_stillGetTheirView() {
        for (EntityExchangeResult<String> res : List.of(
                get("/bff/session", null, "bff_active"),
                get("/bff/session", null, "bff_activeupper"),
                get("/bff/me", "Bearer bff_active", null),
                get("/bff/me", "Bearer bff_active", "bff_active"),
                get("/bff/me", "Bearer " + issuer.mint("someone", List.of("user")), "bff_active"))) {
            assertThat(res.getStatus().value()).isEqualTo(200);
            assertThat(res.getResponseBody()).contains("\"handle\":\"owner\"");
        }
        assertThat(get("/bff/user/_probe", "Bearer bff_active", null).getStatus().value()).isEqualTo(200);
    }

    @Test
    void noSession_is401() {
        assertThat(get("/bff/session", null, null).getStatus().value()).isEqualTo(401);
        assertThat(get("/bff/session", null, "bff_unknown").getStatus().value()).isEqualTo(401);
    }
}
