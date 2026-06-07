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

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.core.context.ReactiveSecurityContextHolder.withSecurityContext;

/**
 * Verifies the token-forwarding {@link org.springframework.web.reactive.function.client.ExchangeFilterFunction}:
 * the caller's Casdoor JWT (from the reactive security context) is re-injected as
 * the outbound {@code Authorization: Bearer <jwt>} header so federation-api scopes
 * the call to the same subject. When no JWT is in context the request goes out
 * unauthenticated (no broader credential is substituted).
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
}
