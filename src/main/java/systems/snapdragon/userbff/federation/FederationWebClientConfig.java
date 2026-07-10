package systems.snapdragon.userbff.federation;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ExchangeFilterFunction;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.netty.http.client.HttpClient;
import systems.snapdragon.userbff.config.BffSessionAuthenticationWebFilter;

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
 *
 * <p>When {@code snapdragon.mtls.client.enabled=true} (default OFF), the WebClient is
 * given a reactor-netty connector that presents this BFF's PKI client identity and
 * trusts the cluster CA, so federation-api's {@code client-auth=need} handshake
 * succeeds. See {@link FederationHttpClientSsl}.
 */
@Configuration
@EnableConfigurationProperties(FederationHttpClientSsl.class)
public class FederationWebClientConfig {

    @Bean
    public FederationApiClient federationApiClient(
            FederationHttpClientSsl mtls,
            @Value("${federation.api.base-url:http://snapdragon-federation-api.snapdragon-backend.svc.cluster.local:8080}") String baseUrl) {
        HttpClient httpClient = mtls.customize(HttpClient.create());
        WebClient web = WebClient.builder()
                .baseUrl(baseUrl)
                .clientConnector(new ReactorClientHttpConnector(httpClient))
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
     *
     * <p>Public + reusable: the media-proxy ({@code MediaWebClientConfig}) reuses this
     * exact filter so the caller's bearer is forwarded only as far as the BFF on the
     * real homeserver upload too — one bearer-forward implementation, no service
     * credential anywhere.
     *
     * <p><b>Synthetic native-login principal is never forwarded.</b>
     * {@code BffSessionAuthenticationWebFilter} wraps a {@code bff_}-session caller's
     * principal in a {@link JwtAuthenticationToken} too (so this service's own
     * {@code @AuthenticationPrincipal Jwt jwt} controllers resolve correctly) — which
     * means the {@code instanceof JwtAuthenticationToken} check above now also matches
     * native-login callers, a side effect that this filter did NOT match before that
     * change (a {@code bff_}-session {@link Authentication} used to be a plain {@code
     * UsernamePasswordAuthenticationToken}). That synthetic {@link Jwt} is never signed,
     * never verifiable by federation-api or the homeserver proxies, and its token value
     * ({@link BffSessionAuthenticationWebFilter#SYNTHETIC_TOKEN_MARKER} + the caller's
     * account id) would leak the caller's real account id in cleartext into an outbound
     * {@code Authorization} header these downstream services previously never received
     * anything on this path. Filtering it out here restores the exact pre-existing
     * behavior — no {@code Authorization} header sent — for a native-login caller, while
     * a real Casdoor JWT's token value is forwarded completely unaffected.
     */
    public static ExchangeFilterFunction bearerTokenForwardingFilter() {
        return (request, next) -> ReactiveSecurityContextHolder.getContext()
                .map(ctx -> ctx.getAuthentication())
                .filter(auth -> auth instanceof JwtAuthenticationToken)
                .map(auth -> ((JwtAuthenticationToken) auth).getToken())
                .map(Jwt::getTokenValue)
                .filter(token -> !token.startsWith(BffSessionAuthenticationWebFilter.SYNTHETIC_TOKEN_MARKER))
                .map(token -> ClientRequest.from(request)
                        .headers(h -> h.setBearerAuth(token))
                        .build())
                .defaultIfEmpty(request)
                .flatMap(next::exchange);
    }

}
