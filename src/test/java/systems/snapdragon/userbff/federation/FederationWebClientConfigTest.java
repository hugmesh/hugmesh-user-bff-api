package systems.snapdragon.userbff.federation;

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
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import systems.snapdragon.userbff.config.BffSessionAuthenticationWebFilter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.core.context.ReactiveSecurityContextHolder.withSecurityContext;

/**
 * Verifies the token-forwarding {@link org.springframework.web.reactive.function.client.ExchangeFilterFunction}:
 * the caller's Casdoor JWT (from the reactive security context) is re-injected as
 * the outbound {@code Authorization: Bearer <jwt>} header so federation-api scopes
 * the call to the same subject. When no JWT is in context the request goes out
 * unauthenticated (no broader credential is substituted).
 *
 * <p>Also verifies the fix for the information-disclosure regression two independent
 * adversarial reviews of PR #108 found: {@code BffSessionAuthenticationWebFilter}
 * wraps a native-login {@code bff_}-session principal in a {@link JwtAuthenticationToken}
 * carrying a SYNTHETIC (never signed) {@link Jwt} whose token value embeds the caller's
 * real account id. Before that change, a {@code bff_}-session {@link
 * org.springframework.security.core.Authentication} was a plain {@code
 * UsernamePasswordAuthenticationToken}, which this filter's {@code instanceof
 * JwtAuthenticationToken} check never matched — no {@code Authorization} header was ever
 * sent to federation-api / the homeserver proxies for a native-login caller. The
 * synthetic-{@link Jwt} change silently activated this filter for native-login callers
 * for the first time, forwarding the account id in cleartext as a purported bearer
 * credential. {@link FederationWebClientConfig#bearerTokenForwardingFilter()} now skips
 * forwarding when the token value carries {@link
 * BffSessionAuthenticationWebFilter#SYNTHETIC_TOKEN_MARKER}, restoring the exact
 * pre-existing "no header sent" behavior for this case, while leaving the real-JWT
 * path (the {@code forwardsCallerJwtAsBearer} test below) completely unaffected.
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

    @Test
    void forwardsCallerJwtAsBearer() {
        Recorder rec = new Recorder();
        WebClient web = WebClient.builder()
                .baseUrl("http://federation")
                .filter(FederationWebClientConfig.bearerTokenForwardingFilter())
                .exchangeFunction(rec)
                .build();

        Jwt jwt = jwt("alice", "the-token-value");
        JwtAuthenticationToken auth = new JwtAuthenticationToken(jwt);

        web.get().uri("/x").retrieve().bodyToMono(String.class)
                .contextWrite(withSecurityContext(Mono.just(new SecurityContextImpl(auth))))
                .block();

        assertThat(rec.requests).hasSize(1);
        assertThat(rec.requests.get(0).headers().getFirst(HttpHeaders.AUTHORIZATION))
                .isEqualTo("Bearer the-token-value");
    }

    @Test
    void noJwtInContext_goesOutUnauthenticated() {
        Recorder rec = new Recorder();
        WebClient web = WebClient.builder()
                .baseUrl("http://federation")
                .filter(FederationWebClientConfig.bearerTokenForwardingFilter())
                .exchangeFunction(rec)
                .build();

        // a non-JWT authentication in context must NOT produce a bearer header
        var auth = new TestingAuthenticationToken("someone", "x");
        web.get().uri("/x").retrieve().bodyToMono(String.class)
                .contextWrite(withSecurityContext(Mono.just(new SecurityContextImpl(auth))))
                .block();

        assertThat(rec.requests).hasSize(1);
        assertThat(rec.requests.get(0).headers().getFirst(HttpHeaders.AUTHORIZATION)).isNull();
    }

    /**
     * Regression test for the information-disclosure gap two independent adversarial
     * reviews of PR #108 found: a native-login (synthetic-{@link Jwt}) {@link
     * JwtAuthenticationToken} in context must produce NO {@code Authorization} header at
     * all — not the synthetic marker, not anything else — exactly like the pre-108
     * {@code UsernamePasswordAuthenticationToken} shape this filter never matched.
     */
    @Test
    void syntheticBffSessionJwtInContext_neverForwardsMarkerOrAnyHeader() {
        Recorder rec = new Recorder();
        WebClient web = WebClient.builder()
                .baseUrl("http://federation")
                .filter(FederationWebClientConfig.bearerTokenForwardingFilter())
                .exchangeFunction(rec)
                .build();

        // Exactly what BffSessionAuthenticationWebFilter.syntheticJwt/authenticationFor
        // build for a resolved bff_ session — never signed, token value is the marker +
        // the caller's real account id.
        Jwt synthetic = jwt("acct-12345",
                BffSessionAuthenticationWebFilter.SYNTHETIC_TOKEN_MARKER + "acct-12345");
        JwtAuthenticationToken auth = new JwtAuthenticationToken(synthetic);

        web.get().uri("/x").retrieve().bodyToMono(String.class)
                .contextWrite(withSecurityContext(Mono.just(new SecurityContextImpl(auth))))
                .block();

        assertThat(rec.requests).hasSize(1);
        assertThat(rec.requests.get(0).headers().getFirst(HttpHeaders.AUTHORIZATION)).isNull();
    }

    /**
     * Companion to the regression test above: a REAL Casdoor-JWT-authenticated {@link
     * JwtAuthenticationToken} whose token value does NOT carry the synthetic marker must
     * be forwarded exactly as before — no regression to the legitimate, working case this
     * filter exists for. Distinct from {@link #forwardsCallerJwtAsBearer()} only in using
     * a token value shaped closer to the synthetic marker's prefix (starts with a similar
     * "bff" fragment) to prove the check is a real prefix match, not an accidental
     * substring/contains check that could also reject unrelated real tokens.
     */
    @Test
    void realCasdoorJwtInContext_stillForwardedUnaffected() {
        Recorder rec = new Recorder();
        WebClient web = WebClient.builder()
                .baseUrl("http://federation")
                .filter(FederationWebClientConfig.bearerTokenForwardingFilter())
                .exchangeFunction(rec)
                .build();

        Jwt real = jwt("alice", "eyJhbGciOiJSUzI1NiJ9.real-casdoor-jwt-payload.signature");
        JwtAuthenticationToken auth = new JwtAuthenticationToken(real);

        web.get().uri("/x").retrieve().bodyToMono(String.class)
                .contextWrite(withSecurityContext(Mono.just(new SecurityContextImpl(auth))))
                .block();

        assertThat(rec.requests).hasSize(1);
        assertThat(rec.requests.get(0).headers().getFirst(HttpHeaders.AUTHORIZATION))
                .isEqualTo("Bearer eyJhbGciOiJSUzI1NiJ9.real-casdoor-jwt-payload.signature");
    }
}
