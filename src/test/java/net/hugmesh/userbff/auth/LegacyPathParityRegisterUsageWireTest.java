package net.hugmesh.userbff.auth;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webflux.test.autoconfigure.WebFluxTest;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.mock.http.client.reactive.MockClientHttpRequest;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import org.springframework.web.reactive.function.client.ExchangeStrategies;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Hooks;
import reactor.core.publisher.Mono;
import net.hugmesh.authcore.config.SessionCookieService;
import net.hugmesh.userbff.config.SecurityConfig;
import net.hugmesh.userbff.hsproxy.HsTokenCustody;
import net.hugmesh.userbff.hsproxy.ServiceTokenBroker;
import net.hugmesh.userbff.web.ApiExceptionHandler;

import java.io.IOException;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * Decision 55 (hugmesh-generator#347, 2026-09-18: "yes — build the internal usage leg"), pinned
 * END TO END against a STUB admin-bff: the REAL {@link AdminBffInternalClient} over a recording
 * {@link ExchangeFunction} that answers admin-bff's {@code /bff/internal/**} routes with the
 * bodies admin-bff actually emits, driven through {@link LegacyPathParityController}'s
 * {@code POST /bff/register/google}/{@code discord} on the real {@link SecurityConfig} chain.
 *
 * <p>What the mock-level pins in {@link LegacyPathParityRegisterTest} cannot show and this can:
 * <ul>
 *   <li>a registration performed here arrives at admin-bff as ONE
 *       {@code POST /bff/internal/usage} whose JSON body is exactly admin-bff's own triple —
 *       the bare lowercased handle, the account's roles verbatim (the lowercase dialect
 *       admin-bff's endpoint requires), {@code "action":"register"} — carrying the internal
 *       token, i.e. the request admin-bff's {@code InternalAccountControllerRecordUsageWireTest}
 *       answers 204;</li>
 *   <li>admin-bff answering that call with a 500, or the connection dropping, changes NOTHING
 *       the caller sees: 200, a session token, and the {@code /sessions} mint still made — the
 *       detachment is real on the wire, not a property of a Mockito stub;</li>
 *   <li>the already-complete input (decision 57) and the uninvited input never produce a
 *       usage request at all.</li>
 * </ul>
 *
 * <p>No live door is exercised: admin-bff itself is the stub below. A person still has to
 * confirm the row on a live mesh's {@code /bff/admin/usage} view (tracked on
 * hugmesh-user-bff-api#19).
 */
@WebFluxTest(controllers = LegacyPathParityController.class)
@Import({SecurityConfig.class, CanonicalIdentityResolver.class, ApiExceptionHandler.class,
        LegacyPathParityRegisterUsageWireTest.StubAdminBff.class})
class LegacyPathParityRegisterUsageWireTest {

    private static final String EMAIL = "alice@example.test";
    private static final String GOOGLE_ID = "google:" + EMAIL;
    private static final String DISCORD_HANDLE = "dragoneer";
    private static final String DISCORD_ID = "discord:" + DISCORD_HANDLE;
    private static final String TOKEN = "bff_from-stub-admin-bff";

    /** One recorded outbound request: method, path, and the JSON body as written to the wire. */
    record Seen(HttpMethod method, String path, String internalToken, String body) {}

    /**
     * The stub admin-bff. Answers the allowlist read, the ensure, and the session mint with
     * admin-bff's real body shapes; the usage endpoint's answer is configurable per test.
     * {@code registrationComplete} on the ensured account is configurable too, to reach the
     * decision-57 branch. Bodies are captured NON-blocking (no {@code block()} on the request
     * thread).
     */
    static class StubAdminBffExchange implements ExchangeFunction {
        final List<Seen> seen = new CopyOnWriteArrayList<>();
        volatile boolean invited = true;
        volatile boolean alreadyComplete = false;
        /** null ⇒ answer {@link #usageStatus}; non-null ⇒ fail the exchange with this error. */
        volatile Throwable usageTransportFailure = null;
        volatile HttpStatus usageStatus = HttpStatus.NO_CONTENT;

        @Override
        public Mono<ClientResponse> exchange(ClientRequest request) {
            MockClientHttpRequest sink = new MockClientHttpRequest(HttpMethod.POST, URI.create("http://admin-bff.test"));
            return request.writeTo(sink, ExchangeStrategies.withDefaults())
                    .then(Mono.defer(sink::getBodyAsString))
                    .defaultIfEmpty("")
                    .flatMap(body -> {
                        String path = request.url().getPath();
                        seen.add(new Seen(request.method(), path,
                                request.headers().getFirst("X-Internal-Token"), body));
                        return respond(path, body);
                    });
        }

        private Mono<ClientResponse> respond(String path, String body) {
            if (path.startsWith("/bff/internal/allowlist/")) {
                return json(HttpStatus.OK, "{\"invited\":" + invited + "}");
            }
            if (path.equals("/bff/internal/accounts/ensure")) {
                boolean discord = body.contains("\"provider\":\"discord\"");
                String id = discord ? DISCORD_ID : GOOGLE_ID;
                String provider = discord ? "discord" : "google";
                String handle = discord ? DISCORD_HANDLE : EMAIL;
                return json(HttpStatus.OK, "{\"id\":\"" + id + "\",\"provider\":\"" + provider
                        + "\",\"handle\":\"" + handle + "\",\"registrationComplete\":" + alreadyComplete
                        + ",\"roles\":[\"user\",\"matrix\"],\"localpart\":\"" + handle.replaceAll("[^a-z0-9]", "")
                        + "\",\"mastodonLocalpart\":\"\"}");
            }
            if (path.equals("/bff/internal/sessions")) {
                String id = body.contains(DISCORD_ID) ? DISCORD_ID : GOOGLE_ID;
                return json(HttpStatus.OK, "{\"token\":\"" + TOKEN + "\",\"accountId\":\"" + id + "\"}");
            }
            if (path.equals("/bff/internal/usage")) {
                if (usageTransportFailure != null) {
                    return Mono.error(usageTransportFailure);
                }
                return Mono.just(ClientResponse.create(usageStatus).build());
            }
            return Mono.just(ClientResponse.create(HttpStatus.NOT_FOUND).build());
        }

        private static Mono<ClientResponse> json(HttpStatus status, String body) {
            return Mono.just(ClientResponse.create(status)
                    .header("Content-Type", "application/json").body(body).build());
        }

        List<Seen> usageCalls() {
            return seen.stream().filter(s -> s.path().equals("/bff/internal/usage")).toList();
        }

        List<Seen> sessionMints() {
            return seen.stream().filter(s -> s.path().equals("/bff/internal/sessions")).toList();
        }
    }

    @TestConfiguration
    static class StubAdminBff {
        @Bean StubAdminBffExchange stubAdminBffExchange() { return new StubAdminBffExchange(); }

        /** The REAL client, built exactly as {@code AdminBffInternalConfig} builds the live one
         *  (base URL + the internal-token default header), over the stub exchange. */
        @Bean AdminBffInternalClient adminBffInternalClient(StubAdminBffExchange exchange) {
            return new AdminBffInternalClient(WebClient.builder()
                    .baseUrl("http://admin-bff.test")
                    .defaultHeader("X-Internal-Token", "s3cr3t-internal")
                    .exchangeFunction(exchange)
                    .build());
        }
    }

    @Autowired ApplicationContext context;
    @Autowired StubAdminBffExchange adminBff;
    WebTestClient client;

    @MockitoBean ReactiveJwtDecoder jwtDecoder;
    @MockitoBean HsTokenCustody custody;
    @MockitoBean ServiceTokenBroker broker;
    @MockitoBean SessionCookieService cookies;

    @BeforeEach
    void setUp() {
        client = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
        when(cookies.enabled()).thenReturn(false);
        adminBff.seen.clear();
        adminBff.invited = true;
        adminBff.alreadyComplete = false;
        adminBff.usageStatus = HttpStatus.NO_CONTENT;
        adminBff.usageTransportFailure = null;
    }

    private WebTestClient.ResponseSpec postGoogle(String email) {
        return client.post().uri("/bff/register/google").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"email\":\"" + email + "\"}").exchange();
    }

    private WebTestClient.ResponseSpec postDiscord(String username) {
        return client.post().uri("/bff/register/discord").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"username\":\"" + username + "\"}").exchange();
    }

    @Test
    void google_registration_arrivesAtAdminBffAsOneUsagePost_withItsOwnTriple() {
        postGoogle("Alice@Example.TEST")
                .expectStatus().isOk()
                .expectBody().jsonPath("$.token").isEqualTo(TOKEN);

        List<Seen> usage = adminBff.usageCalls();
        assertThat(usage).hasSize(1);
        Seen u = usage.get(0);
        assertThat(u.method()).isEqualTo(HttpMethod.POST);
        assertThat(u.internalToken()).isEqualTo("s3cr3t-internal");
        // The bare LOWERCASED handle (not google:alice@…), the roles admin-bff's own ensure
        // answered with — verbatim, lowercase — and the literal "register".
        assertThat(u.body()).isEqualTo(
                "{\"handle\":\"" + EMAIL + "\",\"roles\":[\"user\",\"matrix\"],\"action\":\"register\"}");
        // Ordering parity with admin-bff's emitAndSession: the usage row is fired BEFORE the
        // session mint.
        List<String> paths = adminBff.seen.stream().map(Seen::path).toList();
        assertThat(paths.indexOf("/bff/internal/usage")).isLessThan(paths.indexOf("/bff/internal/sessions"));
    }

    @Test
    void discord_registration_arrivesAtAdminBffAsOneUsagePost_underTheBareHandle() {
        postDiscord(DISCORD_HANDLE).expectStatus().isOk();

        List<Seen> usage = adminBff.usageCalls();
        assertThat(usage).hasSize(1);
        assertThat(usage.get(0).body()).isEqualTo(
                "{\"handle\":\"" + DISCORD_HANDLE + "\",\"roles\":[\"user\",\"matrix\"],\"action\":\"register\"}");
    }

    /** admin-bff's usage endpoint 500s (its ClickHouse fallback failed) — the caller still gets
     *  its session, and the mint was still made. */
    @Test
    void adminBffUsage500_registrationStillSucceeds_withASession() {
        adminBff.usageStatus = HttpStatus.INTERNAL_SERVER_ERROR;

        postGoogle(EMAIL)
                .expectStatus().isOk()
                .expectBody().jsonPath("$.token").isEqualTo(TOKEN);

        assertThat(adminBff.usageCalls()).hasSize(1);
        assertThat(adminBff.sessionMints()).hasSize(1);
    }

    /** The connection to admin-bff drops on the usage call only — same outcome. */
    @Test
    void adminBffUsageTransportFailure_registrationStillSucceeds_withASession() {
        adminBff.usageTransportFailure = new IOException("connection reset by peer");

        postDiscord(DISCORD_HANDLE)
                .expectStatus().isOk()
                .expectBody().jsonPath("$.token").isEqualTo(TOKEN);

        assertThat(adminBff.sessionMints()).hasSize(1);
    }

    /**
     * The failure of the detached usage call is CONSUMED by the controller's error callback (a
     * WARN), not dropped: a bare {@code subscribe()} would hand it to Reactor's
     * {@code onErrorDropped} hook as an {@code ErrorCallbackNotImplemented}, which Reactor logs
     * at ERROR with a full stack trace on every admin-bff hiccup. Pinned for both failure
     * shapes (an admin-bff 5xx and a dropped connection) by installing a capturing hook for the
     * duration of the request.
     */
    @Test
    void usageFailure_isHandledByTheController_neverReachesReactorsOnErrorDropped() {
        List<Throwable> dropped = new CopyOnWriteArrayList<>();
        Hooks.onErrorDropped(dropped::add);
        try {
            adminBff.usageStatus = HttpStatus.INTERNAL_SERVER_ERROR;
            postGoogle(EMAIL).expectStatus().isOk();

            adminBff.usageStatus = HttpStatus.NO_CONTENT;
            adminBff.usageTransportFailure = new IOException("connection reset by peer");
            postDiscord(DISCORD_HANDLE).expectStatus().isOk();

            assertThat(adminBff.usageCalls()).hasSize(2);
            assertThat(dropped).as("errors routed to Reactor's onErrorDropped hook").isEmpty();
        } finally {
            Hooks.resetOnErrorDropped();
        }
    }

    /** Decision 57 on the wire: the already-complete input is a 409 and admin-bff sees NO usage
     *  request and NO session mint — only the allowlist read and the ensure. */
    @Test
    void alreadyCompleteAccount_is409_andAdminBffSeesNoUsagePostAndNoMint() {
        adminBff.alreadyComplete = true;

        postGoogle(EMAIL).expectStatus().isEqualTo(HttpStatus.CONFLICT);

        assertThat(adminBff.usageCalls()).isEmpty();
        assertThat(adminBff.sessionMints()).isEmpty();
        assertThat(adminBff.seen.stream().map(Seen::path).toList())
                .containsExactly("/bff/internal/allowlist/google/" + EMAIL, "/bff/internal/accounts/ensure");
    }

    @Test
    void uninvited_is403_andAdminBffSeesNoUsagePost() {
        adminBff.invited = false;

        postGoogle(EMAIL).expectStatus().isForbidden();

        assertThat(adminBff.usageCalls()).isEmpty();
        assertThat(adminBff.sessionMints()).isEmpty();
    }
}
