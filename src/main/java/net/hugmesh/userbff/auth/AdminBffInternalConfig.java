package net.hugmesh.userbff.auth;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.netty.http.client.HttpClient;
import net.hugmesh.userbff.federation.FederationHttpClientSsl;

/**
 * Wires the {@link AdminBffInternalClient}'s reactive {@link WebClient} to
 * hugmesh-admin-bff's internal surface, REUSING the established outbound patterns
 * in this repo:
 *
 * <ul>
 *   <li>the mTLS connector of {@link FederationHttpClientSsl} — presents this BFF's
 *       cluster-CA client identity + trusts the cluster CA when
 *       {@code hugmesh.mtls.client.enabled=true} (default OFF ⇒ plain HTTP locally),
 *       exactly as {@code FederationWebClientConfig} / {@code client.RevocationWriter}
 *       do; and</li>
 *   <li>an outbound {@code X-Internal-Token} default header (header name
 *       {@code app.internal.token-header}, value {@code app.internal.token}) — the
 *       OUTBOUND counterpart to auth-core's INBOUND {@code InternalTokenWebFilter} on
 *       admin-bff. Stamped ONLY when the token is non-blank, so dev/test/CI (blank
 *       token) call without a header and admin-bff's filter is a matching no-op.</li>
 * </ul>
 *
 * <p>GATED, fail-closed-stubbed: the live {@link WebClient} is built ONLY when
 * {@code app.bff.oidc.enabled=true}. With the surface dark (the default), the bean is a
 * stub {@link AdminBffInternalClient} holding a {@code null} client whose every method
 * errors — so a disabled login surface can never silently provision an account/session.
 * This deliberately differs from {@code RevocationWriter}'s best-effort no-op stub:
 * account/session ops on the login path are security-critical and must FAIL CLOSED.
 */
@Configuration
public class AdminBffInternalConfig {

    private static final Logger log = LoggerFactory.getLogger(AdminBffInternalConfig.class);

    @Bean
    public AdminBffInternalClient adminBffInternalClient(
            FederationHttpClientSsl mtls,
            @Value("${app.bff.oidc.enabled:false}") boolean oidcEnabled,
            @Value("${app.admin-bff.internal.base-url:http://hugmesh-admin-bff-api.hugmesh-backend.svc.cluster.local:8080}")
            String baseUrl,
            @Value("${app.internal.token-header:X-Internal-Token}") String tokenHeader,
            @Value("${app.internal.token:}") String internalToken) {

        if (!oidcEnabled) {
            log.info("[admin-bff-internal] OIDC surface disabled (app.bff.oidc.enabled=false) — "
                    + "internal client ships as a fail-closed STUB (no account/session op runs)");
            return new AdminBffInternalClient(null);
        }

        HttpClient httpClient = mtls.customize(HttpClient.create());
        WebClient.Builder builder = WebClient.builder()
                .baseUrl(baseUrl)
                .clientConnector(new ReactorClientHttpConnector(httpClient));
        if (internalToken != null && !internalToken.isBlank()) {
            builder.defaultHeader(tokenHeader, internalToken);
            log.info("[admin-bff-internal] live client → {} (X-Internal-Token stamp ON)", baseUrl);
        } else {
            // No internal token configured: admin-bff's inbound InternalTokenWebFilter is
            // a matching no-op when its own token is blank, so this is the dev/test/CI
            // posture — never an in-cluster posture (the deployment sets INTERNAL_TOKEN).
            log.warn("[admin-bff-internal] live client → {} but app.internal.token is BLANK — "
                    + "no X-Internal-Token stamp (expected only in dev/test/CI)", baseUrl);
        }
        return new AdminBffInternalClient(builder.build());
    }
}
