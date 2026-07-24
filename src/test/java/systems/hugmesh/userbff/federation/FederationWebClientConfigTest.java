package systems.hugmesh.userbff.federation;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import systems.hugmesh.userbff.auth.AdminBffInternalClient;
import systems.hugmesh.userbff.config.BffSessionAuthenticationWebFilter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.core.context.ReactiveSecurityContextHolder.withSecurityContext;

/**
 * Verifies the token-forwarding {@link org.springframework.web.reactive.function.client.ExchangeFilterFunction}.
 *
 * <p>Two carrier shapes are forwarded as the real caller:
 * <ul>
 *   <li>a REAL Casdoor JWT — its token value is re-injected verbatim as {@code
 *       Authorization: Bearer <jwt>};</li>
 *   <li>a NATIVE-LOGIN session — the principal is a SYNTHETIC {@link Jwt} (token value =
 *       {@link BffSessionAuthenticationWebFilter#SYNTHETIC_TOKEN_MARKER} + account id, NOT a
 *       credential); the raw {@code bff_} token stashed in the Reactor context by {@code
 *       BffSessionAuthenticationWebFilter} is swapped for a custody JWT via {@link
 *       AdminBffInternalClient#exchangeSession} and THAT is forwarded.</li>
 * </ul>
 *
 * <p>Fail-closed invariants asserted below: the synthetic marker is NEVER forwarded, the
 * raw {@code bff_} token is NEVER forwarded, and any exchange failure / missing context
 * token results in NO {@code Authorization} header (federation-api then 401s) — never an
 * unauthenticated success or a leaked credential.
 */
class FederationWebClientConfigTest {

    static class Recorder implements ExchangeFunction {
        final List<ClientRequest> requests = new ArrayList<>();
        @Override public Mono<ClientResponse> exchange(ClientRequest request) {
            requests.add(request);
            return Mono.just(ClientResponse.create(HttpStatus.OK).body("[]").build());
        }
    }

    private static Jwt jwt(String subject, String tokenValue) {
        return Jwt.withTokenValue(tokenValue).header("alg", "none")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(3600))
                .subject(subject).build();
    }

    private static WebClient webWith(AdminBffInternalClient adminBff, Recorder rec) {
        return WebClient.builder()
                .baseUrl("http://federation")
                .filter(FederationWebClientConfig.bearerTokenForwardingFilter(adminBff))
                .exchangeFunction(rec)
                .build();
    }

    private static String authHeader(Recorder rec) {
        assertThat(rec.requests).hasSize(1);
        return rec.requests.get(0).headers().getFirst(HttpHeaders.AUTHORIZATION);
    }

    // ── real Casdoor JWT — forwarded verbatim (unchanged) ─────────────────────

    @Test
    void forwardsCallerJwtAsBearer() {
        AdminBffInternalClient adminBff = mock(AdminBffInternalClient.class);
        Recorder rec = new Recorder();
        JwtAuthenticationToken auth = new JwtAuthenticationToken(jwt("alice", "the-token-value"));

        webWith(adminBff, rec).get().uri("/x").retrieve().bodyToMono(String.class)
                .contextWrite(withSecurityContext(Mono.just(new SecurityContextImpl(auth))))
                .block();

        assertThat(authHeader(rec)).isEqualTo("Bearer the-token-value");
        // A real JWT never touches the exchange back-channel.
        verify(adminBff, never()).exchangeSession(anyString());
    }

    @Test
    void realCasdoorJwtInContext_stillForwardedUnaffected() {
        AdminBffInternalClient adminBff = mock(AdminBffInternalClient.class);
        Recorder rec = new Recorder();
        // Token value shaped close to (but NOT) the synthetic marker prefix — proves the
        // check is a real prefix match, not an accidental substring reject.
        Jwt real = jwt("alice", "eyJhbGciOiJSUzI1NiJ9.real-casdoor-jwt-payload.signature");
        JwtAuthenticationToken auth = new JwtAuthenticationToken(real);

        webWith(adminBff, rec).get().uri("/x").retrieve().bodyToMono(String.class)
                .contextWrite(withSecurityContext(Mono.just(new SecurityContextImpl(auth))))
                .block();

        assertThat(authHeader(rec)).isEqualTo("Bearer eyJhbGciOiJSUzI1NiJ9.real-casdoor-jwt-payload.signature");
        verify(adminBff, never()).exchangeSession(anyString());
    }

    // ── no / non-JWT auth in context — no bearer ──────────────────────────────

    @Test
    void noJwtInContext_goesOutUnauthenticated() {
        AdminBffInternalClient adminBff = mock(AdminBffInternalClient.class);
        Recorder rec = new Recorder();
        var auth = new TestingAuthenticationToken("someone", "x");

        webWith(adminBff, rec).get().uri("/x").retrieve().bodyToMono(String.class)
                .contextWrite(withSecurityContext(Mono.just(new SecurityContextImpl(auth))))
                .block();

        assertThat(authHeader(rec)).isNull();
        verify(adminBff, never()).exchangeSession(anyString());
    }

    // ── native-login synthetic principal — exchange the stashed bff_ token ────

    @Test
    void syntheticBffSessionJwt_withStashedToken_forwardsExchangedCustodyJwt() {
        AdminBffInternalClient adminBff = mock(AdminBffInternalClient.class);
        when(adminBff.exchangeSession("bff_rawtoken")).thenReturn(Mono.just("custody-jwt-abc"));
        Recorder rec = new Recorder();

        Jwt synthetic = jwt("acct-12345",
                BffSessionAuthenticationWebFilter.SYNTHETIC_TOKEN_MARKER + "acct-12345");
        JwtAuthenticationToken auth = new JwtAuthenticationToken(synthetic);

        webWith(adminBff, rec).get().uri("/x").retrieve().bodyToMono(String.class)
                .contextWrite(ctx -> ctx.put(
                        BffSessionAuthenticationWebFilter.BFF_SESSION_TOKEN_CONTEXT_KEY, "bff_rawtoken"))
                .contextWrite(withSecurityContext(Mono.just(new SecurityContextImpl(auth))))
                .block();

        // Forwards the EXCHANGED custody JWT — never the synthetic marker, never the raw bff_.
        assertThat(authHeader(rec)).isEqualTo("Bearer custody-jwt-abc");
        verify(adminBff).exchangeSession("bff_rawtoken");
    }

    @Test
    void syntheticBffSessionJwt_neverForwardsMarkerOrRawToken() {
        AdminBffInternalClient adminBff = mock(AdminBffInternalClient.class);
        when(adminBff.exchangeSession("bff_rawtoken")).thenReturn(Mono.just("custody-jwt-abc"));
        Recorder rec = new Recorder();
        Jwt synthetic = jwt("acct-9",
                BffSessionAuthenticationWebFilter.SYNTHETIC_TOKEN_MARKER + "acct-9");

        webWith(adminBff, rec).get().uri("/x").retrieve().bodyToMono(String.class)
                .contextWrite(ctx -> ctx.put(
                        BffSessionAuthenticationWebFilter.BFF_SESSION_TOKEN_CONTEXT_KEY, "bff_rawtoken"))
                .contextWrite(withSecurityContext(Mono.just(new SecurityContextImpl(new JwtAuthenticationToken(synthetic)))))
                .block();

        String header = authHeader(rec);
        assertThat(header).isEqualTo("Bearer custody-jwt-abc");
        assertThat(header).doesNotContain(BffSessionAuthenticationWebFilter.SYNTHETIC_TOKEN_MARKER);
        assertThat(header).doesNotContain("bff_rawtoken");
    }

    @Test
    void syntheticBffSessionJwt_exchangeFails_noBearerForwarded() {
        AdminBffInternalClient adminBff = mock(AdminBffInternalClient.class);
        // Suspended (403) / expired (404) / custody-disabled (503) all surface as an error.
        when(adminBff.exchangeSession("bff_suspended"))
                .thenReturn(Mono.error(new ResponseStatusException(HttpStatus.FORBIDDEN, "suspended")));
        Recorder rec = new Recorder();
        Jwt synthetic = jwt("acct-s",
                BffSessionAuthenticationWebFilter.SYNTHETIC_TOKEN_MARKER + "acct-s");

        webWith(adminBff, rec).get().uri("/x").retrieve().bodyToMono(String.class)
                .contextWrite(ctx -> ctx.put(
                        BffSessionAuthenticationWebFilter.BFF_SESSION_TOKEN_CONTEXT_KEY, "bff_suspended"))
                .contextWrite(withSecurityContext(Mono.just(new SecurityContextImpl(new JwtAuthenticationToken(synthetic)))))
                .block();

        // Exchange failed → NO Authorization header (federation-api fail-closes 401).
        assertThat(authHeader(rec)).isNull();
        verify(adminBff).exchangeSession("bff_suspended");
    }

    @Test
    void syntheticBffSessionJwt_noStashedToken_noBearerForwarded() {
        AdminBffInternalClient adminBff = mock(AdminBffInternalClient.class);
        Recorder rec = new Recorder();
        Jwt synthetic = jwt("acct-x",
                BffSessionAuthenticationWebFilter.SYNTHETIC_TOKEN_MARKER + "acct-x");

        // No BFF_SESSION_TOKEN_CONTEXT_KEY in context.
        webWith(adminBff, rec).get().uri("/x").retrieve().bodyToMono(String.class)
                .contextWrite(withSecurityContext(Mono.just(new SecurityContextImpl(new JwtAuthenticationToken(synthetic)))))
                .block();

        assertThat(authHeader(rec)).isNull();
        // Never attempt an exchange without a token.
        verify(adminBff, never()).exchangeSession(anyString());
    }
}
