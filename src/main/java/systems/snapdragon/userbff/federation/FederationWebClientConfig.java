package systems.snapdragon.userbff.federation;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ExchangeFilterFunction;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

/**
 * Wires the reactive {@link WebClient} the {@link FederationApiClient} uses to call
 * snapdragon-federation-api, with a token-injecting {@link ExchangeFilterFunction}.
 *
 * <p>The filter reads the CURRENT request's Casdoor JWT out of the reactive
 * security context and re-injects its raw token value as {@code Authorization:
 * Bearer <jwt>} on the outbound call. This forwards the caller's identity to
 * federation-api so federation-api scopes {@code /bundles/mine} (and records bundle
 * ownership) to the SAME subject — owner-enforcement holds end-to-end with no
 * service credential that could read another user's data.
 *
 * <p>Base URL defaults to the in-cluster DNS (env-overridable via
 * {@code FEDERATION_API_BASE_URL}).
 */
@Configuration
public class FederationWebClientConfig {

    @Bean
    public FederationApiClient federationApiClient(
            @Value("${federation.api.base-url:http://snapdragon-federation-api.snapdragon-backend.svc.cluster.local:8080}") String baseUrl) {
        WebClient web = WebClient.builder()
                .baseUrl(baseUrl)
                .filter(bearerTokenForwardingFilter())
                .build();
        return new FederationApiClient(web);
    }

    /**
     * Re-injects the caller's Casdoor JWT (from the reactive security context) as
     * the outbound {@code Authorization} header. If there is no JWT in context (e.g.
     * a non-request-scoped call) the request goes out unauthenticated and
     * federation-api will reject it — by design, the BFF never substitutes a
     * broader-scoped credential.
     */
    static ExchangeFilterFunction bearerTokenForwardingFilter() {
        return (request, next) -> ReactiveSecurityContextHolder.getContext()
                .map(ctx -> ctx.getAuthentication())
                .filter(auth -> auth instanceof JwtAuthenticationToken)
                .map(auth -> ((JwtAuthenticationToken) auth).getToken())
                .map(Jwt::getTokenValue)
                .map(token -> ClientRequest.from(request)
                        .headers(h -> h.setBearerAuth(token))
                        .build())
                .defaultIfEmpty(request)
                .flatMap(next::exchange);
    }

    /** Header name kept referenced so the import/intent is explicit. */
    @SuppressWarnings("unused")
    private static final String AUTH = HttpHeaders.AUTHORIZATION;
}
