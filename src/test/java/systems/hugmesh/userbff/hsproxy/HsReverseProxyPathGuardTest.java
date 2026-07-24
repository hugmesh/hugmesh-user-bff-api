package systems.hugmesh.userbff.hsproxy;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import systems.hugmesh.commons.web.ApiException;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * SSRF / token+mTLS-cert leak guard for {@link HsReverseProxy#forward}.
 *
 * <p>The reverse-proxy injects the decrypted homeserver-native Bearer and rides the BFF
 * mTLS client cert on the upstream leg. A {@code upstreamPath} that is a scheme-relative
 * authority ({@code //evil.com/x}), a backslash variant ({@code /\evil}, {@code \evil}) or
 * an embedded absolute URL ({@code https://evil}) would override the mTLS WebClient's
 * baseUrl host and leak BOTH secrets to an attacker host. These tests assert such hostile
 * paths are REJECTED with a 400 ({@link ApiException}) BEFORE any token is loaded or any
 * upstream request is built, while a normal single-{@code '/'}-leading relative path is
 * ALLOWED (it gets past the guard to the token-load step).
 */
class HsReverseProxyPathGuardTest {

    /** A WebClient that must NEVER be dialed in these tests — the guard fires (reject) or
     *  the empty token-load fails closed (allow) before any upstream call. A reachable-
     *  looking-but-unrouted base makes an accidental dial loud rather than silent. */
    private static final WebClient NEVER_DIALED =
            WebClient.builder().baseUrl("https://tuwunel-proxy.invalid:4443").build();

    /**
     * Drive {@link HsReverseProxy#forward} with the given homeserver-native path. The
     * exchange uses a FIXED valid request URI (the guard validates the {@code upstreamPath}
     * ARGUMENT, not the exchange path — the exchange is only read for the raw query), so a
     * hostile string is exercised purely as the upstream path. The loadToken is EMPTY so an
     * ALLOWED path fails closed with a 401 ({@code "no custody token"}) — proving it got
     * PAST the guard — whereas a REJECTED path errors with a 400 {@link ApiException} from
     * the guard itself, before the token-load step.
     */
    private Mono<Void> forward(String upstreamPath) {
        HsReverseProxy proxy = new HsReverseProxy(NEVER_DIALED);
        ServerWebExchange exchange =
                MockServerWebExchange.from(MockServerHttpRequest.get("/bff/user/matrix").build());
        return proxy.forward(exchange, upstreamPath, Mono.empty(), Mono.empty());
    }

    private void assertRejected(String hostilePath) {
        StepVerifier.create(forward(hostilePath))
                .expectErrorSatisfies(err -> {
                    assertThat(err).isInstanceOf(ApiException.class);
                    assertThat(((ApiException) err).status()).isEqualTo(HttpStatus.BAD_REQUEST);
                })
                .verify();
    }

    @Test
    void rejects_schemeRelativeAuthority_overridingHost() {
        // GET /bff/user/matrix//evil.com/x → upstreamPath "//evil.com/x" is an authority.
        assertRejected("//evil.com/x");
    }

    @Test
    void rejects_backslashAfterLeadingSlash() {
        // '/\evil' is folded to '//evil' by many URL parsers → authority override.
        assertRejected("/\\evil");
    }

    @Test
    void rejects_leadingBackslash() {
        assertRejected("\\evil.com/x");
    }

    @Test
    void rejects_embeddedAbsoluteUrl() {
        assertRejected("https://evil.example/x");
    }

    @Test
    void rejects_embeddedSchemeMidPath() {
        assertRejected("/x/https://evil/y");
    }

    @Test
    void rejects_emptyAndNonSlashLeading() {
        assertRejected("");
        assertRejected("evil.com/x");
    }

    @Test
    void allows_normalMatrixSyncPath_passesGuardThenFailsClosedOnEmptyToken() {
        // A legitimate single-'/'-leading relative path passes the guard and proceeds to
        // the token-load step; with an EMPTY token that is a fail-closed 401 (NOT a 400),
        // which proves the path was ALLOWED past the SSRF guard.
        StepVerifier.create(forward("/_matrix/client/v3/sync"))
                .expectErrorSatisfies(err -> {
                    assertThat(err).isInstanceOf(ResponseStatusException.class);
                    assertThat(((ResponseStatusException) err).getStatusCode())
                            .isEqualTo(HttpStatus.UNAUTHORIZED);
                    // crucially NOT an ApiException(400) from the guard
                    assertThat(err).isNotInstanceOf(ApiException.class);
                })
                .verify();
    }

    @Test
    void allows_normalMastodonStreamingPath_passesGuard() {
        StepVerifier.create(forward("/api/v1/streaming/user"))
                .expectErrorSatisfies(err ->
                        assertThat(err).isInstanceOf(ResponseStatusException.class))
                .verify();
    }
}
