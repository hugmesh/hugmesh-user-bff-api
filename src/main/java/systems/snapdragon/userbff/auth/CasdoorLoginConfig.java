package systems.snapdragon.userbff.auth;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.client.WebClient;

/**
 * Wires the {@link CasdoorLoginClient} to Casdoor's INTERNAL, in-cluster base
 * ({@code app.bff.oidc.login-base}) so the browser-facing issuer is NEVER used for the
 * server-side credential check. GATED, fail-closed-stubbed exactly like
 * {@link AdminBffInternalConfig} and the auth-core {@code OidcExchangeConfig}: the live
 * {@link WebClient} is built ONLY when {@code app.bff.oidc.enabled=true}; with the surface
 * dark (the default) the bean holds a {@code null} client and every login call errors, so a
 * disabled surface can never verify a credential.
 *
 * <p>The Casdoor base here is DELIBERATELY the internal one — plain HTTP inside the mesh,
 * no mTLS (matching the auth-core {@code OidcExchangeClient}'s plain WebClient) — and MUST
 * NOT be the browser-facing {@code CASDOOR_ISSUER_URI}. {@code client-id} is REUSED from
 * {@code app.bff.oidc.client-id} so the authorize call and the auth-core token exchange
 * present the same OIDC client (a PKCE code is only redeemable by the client that requested it).
 */
@Configuration
public class CasdoorLoginConfig {

    private static final Logger log = LoggerFactory.getLogger(CasdoorLoginConfig.class);

    @Bean
    public CasdoorLoginClient casdoorLoginClient(
            @Value("${app.bff.oidc.enabled:false}") boolean oidcEnabled,
            @Value("${app.bff.oidc.login-base:http://casdoor.snapdragon-pki.svc.cluster.local:8000}")
            String loginBase,
            @Value("${app.bff.oidc.login-path:/api/login}") String loginPath,
            @Value("${app.bff.oidc.client-id:user-bff}") String clientId,
            @Value("${app.bff.oidc.application:app-user-bff}") String application,
            @Value("${app.bff.oidc.organization:${casdoor.organization:snapdragon}}") String organization,
            @Value("${app.bff.oidc.scope:openid profile email}") String scope) {

        if (!oidcEnabled) {
            log.info("[casdoor-login] OIDC surface disabled (app.bff.oidc.enabled=false) — "
                    + "native-login client ships as a fail-closed STUB (no credential check runs)");
            return new CasdoorLoginClient(null, loginPath, clientId, application, organization, scope);
        }

        // Plain WebClient over the INTERNAL casdoor base — never the browser-facing issuer.
        WebClient http = WebClient.builder().baseUrl(loginBase).build();
        log.info("[casdoor-login] live native-login client → {} (application={}, clientId={})",
                loginBase, application, clientId);
        return new CasdoorLoginClient(http, loginPath, clientId, application, organization, scope);
    }
}
