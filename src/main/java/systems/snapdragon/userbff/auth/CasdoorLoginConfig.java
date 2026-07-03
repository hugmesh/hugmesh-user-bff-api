package systems.snapdragon.userbff.auth;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.netty.http.client.HttpClient;
import systems.snapdragon.userbff.federation.FederationHttpClientSsl;

/**
 * Wires the {@link CasdoorLoginClient} to Casdoor's INTERNAL, in-cluster base
 * ({@code app.bff.oidc.login-base}) so the browser-facing issuer is NEVER used for the
 * server-side credential check. GATED, fail-closed-stubbed exactly like
 * {@link AdminBffInternalConfig} and the auth-core {@code OidcExchangeConfig}: the live
 * {@link WebClient} is built ONLY when {@code app.bff.oidc.enabled=true}; with the surface
 * dark (the default) the bean holds a {@code null} client and every login call errors, so a
 * disabled surface can never verify a credential.
 *
 * <p>The Casdoor base here is DELIBERATELY the internal one — never the browser-facing
 * {@code CASDOOR_ISSUER_URI}. {@code client-id} is REUSED from {@code app.bff.oidc.client-id}
 * so the authorize call and the auth-core token exchange present the same OIDC client (a PKCE
 * code is only redeemable by the client that requested it).
 *
 * <p><b>Outbound transport.</b> This is the leg that carries the user's PLAINTEXT password to
 * Casdoor's {@code /api/login}, so its connector is built through {@link FederationHttpClientSsl}
 * — the same gated ({@code snapdragon.mtls.client.enabled}, default OFF) client-cert +
 * cluster-CA connector the federation and admin-bff-internal legs already use. With the gate off
 * (local/dev/CI, or a service mesh that already supplies transparent mTLS) the connector is the
 * plain default and nothing changes. To ACTIVATE app-level protection on this hop: set
 * {@code snapdragon.mtls.client.enabled=true}, mount the PKCS12 stores, AND point
 * {@code app.bff.oidc.login-base} at the HTTPS in-cluster Casdoor endpoint (reactor-netty only
 * negotiates TLS for an {@code https://} base) — then the password rides an encrypted,
 * mutually-authenticated channel instead of plaintext HTTP.
 */
@Configuration
@EnableConfigurationProperties(FederationHttpClientSsl.class)
public class CasdoorLoginConfig {

    private static final Logger log = LoggerFactory.getLogger(CasdoorLoginConfig.class);

    @Bean
    public CasdoorLoginClient casdoorLoginClient(
            FederationHttpClientSsl mtls,
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

        // WebClient over the INTERNAL casdoor base — never the browser-facing issuer. The
        // connector carries the gated client-mTLS identity (a no-op unless
        // snapdragon.mtls.client.enabled=true + an https login-base), so this password-bearing
        // leg can present a client cert + ride TLS in-cluster exactly like the federation and
        // admin-bff-internal legs.
        HttpClient httpClient = mtls.customize(HttpClient.create());
        WebClient http = WebClient.builder()
                .baseUrl(loginBase)
                .clientConnector(new ReactorClientHttpConnector(httpClient))
                .build();
        log.info("[casdoor-login] live native-login client → {} (application={}, clientId={}; "
                + "outbound mTLS gate snapdragon.mtls.client.enabled={})",
                loginBase, application, clientId, mtls.isEnabled());
        return new CasdoorLoginClient(http, loginPath, clientId, application, organization, scope);
    }
}
