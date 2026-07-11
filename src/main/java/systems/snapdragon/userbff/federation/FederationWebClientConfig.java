package systems.snapdragon.userbff.federation;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ExchangeFilterFunction;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import reactor.netty.http.client.HttpClient;
import systems.snapdragon.userbff.auth.AdminBffInternalClient;
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
            AdminBffInternalClient adminBff,
            @Value("${federation.api.base-url:http://snapdragon-federation-api.snapdragon-backend.svc.cluster.local:8080}") String baseUrl) {
        HttpClient httpClient = mtls.customize(HttpClient.create());
        WebClient web = WebClient.builder()
                .baseUrl(baseUrl)
                .clientConnector(new ReactorClientHttpConnector(httpClient))
                .filter(bearerTokenForwardingFilter(adminBff))
                .build();
        return new FederationApiClient(web);
    }

    /**
     * Forwards the caller's identity to federation-api / the homeserver proxies as an
     * {@code Authorization: Bearer} header, so those services scope owner-enforced reads
     * ({@code /bundles/mine}) and record ownership to the SAME subject — no broader-scoped
     * service credential anywhere.
     *
     * <p>Public + reusable: the media-proxy ({@code MediaWebClientConfig}) reuses this exact
     * filter so there is one bearer-forward implementation.
     *
     * <p><b>Two carrier shapes, both forwarded as the real user:</b>
     * <ul>
     *   <li><b>Real Casdoor JWT</b> (a genuine resource-server token): its token value is
     *       forwarded verbatim, exactly as before.</li>
     *   <li><b>Native-login session</b> ({@code BffSessionAuthenticationWebFilter} wraps the
     *       principal in a SYNTHETIC {@link JwtAuthenticationToken} whose token value is a
     *       non-forwardable marker, not a credential): the raw {@code bff_} session token —
     *       stashed in the Reactor context by that filter under {@link
     *       BffSessionAuthenticationWebFilter#BFF_SESSION_TOKEN_CONTEXT_KEY} — is swapped for
     *       the internal custody Casdoor JWT via admin-bff ({@link
     *       AdminBffInternalClient#exchangeSession}, the SAME back-channel the gateway's own
     *       {@code BffJwtExchangeWebFilter} uses) and THAT real bearer is forwarded. admin-bff's
     *       exchange endpoint fail-closes a suspended/banned session (403), so a curtailed
     *       account never gets a usable bearer. Before this, the synthetic marker was
     *       filtered OUT entirely (no bearer sent → federation-api 401), so every
     *       federation-backed / homeserver-proxy feature was dead for native-login callers.</li>
     * </ul>
     *
     * <p><b>Fail-closed.</b> The synthetic marker is NEVER forwarded (it embeds the account
     * id in cleartext and is unverifiable); nor is the raw {@code bff_} token (a live
     * credential). If the context has no session token, or the exchange fails (suspended
     * 403, expired 404, custody-disabled 503, timeout), the request goes out with NO
     * {@code Authorization} header — federation-api then rejects it 401, exactly the safe
     * pre-existing outcome, never an unauthenticated success or a leaked credential.
     */
    public static ExchangeFilterFunction bearerTokenForwardingFilter(AdminBffInternalClient adminBff) {
        return (request, next) -> ReactiveSecurityContextHolder.getContext()
                .map(SecurityContext::getAuthentication)
                .filter(auth -> auth instanceof JwtAuthenticationToken)
                .map(auth -> ((JwtAuthenticationToken) auth).getToken().getTokenValue())
                .flatMap(tokenValue -> tokenValue.startsWith(BffSessionAuthenticationWebFilter.SYNTHETIC_TOKEN_MARKER)
                        // Native-login: swap the raw bff_ session (from context) for a custody JWT.
                        ? exchangedBearer(adminBff, request)
                        // Real Casdoor JWT: forward its token value verbatim.
                        : Mono.just(withBearer(request, tokenValue)))
                .defaultIfEmpty(request)
                .flatMap(next::exchange);
    }

    /** Swap the context-stashed raw {@code bff_} session for a custody JWT and attach it;
     *  fail-closed to NO bearer (never the raw token, never the marker) on any failure. */
    private static Mono<ClientRequest> exchangedBearer(AdminBffInternalClient adminBff, ClientRequest request) {
        return Mono.deferContextual(ctx -> {
            String bffToken = ctx.<String>getOrEmpty(BffSessionAuthenticationWebFilter.BFF_SESSION_TOKEN_CONTEXT_KEY)
                    .orElse(null);
            if (bffToken == null || bffToken.isBlank()) {
                // Authenticated synthetic principal but no session token in context — should
                // not happen (the bridge always stashes it), but send no bearer rather than
                // guess: federation-api fail-closes with a 401.
                return Mono.just(request);
            }
            return adminBff.exchangeSession(bffToken)
                    .map(jwt -> withBearer(request, jwt))
                    .onErrorReturn(request);
        });
    }

    private static ClientRequest withBearer(ClientRequest request, String token) {
        return ClientRequest.from(request).headers(h -> h.setBearerAuth(token)).build();
    }

}
