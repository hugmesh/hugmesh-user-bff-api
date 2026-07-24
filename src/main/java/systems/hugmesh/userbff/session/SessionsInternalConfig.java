package systems.hugmesh.userbff.session;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.netty.http.client.HttpClient;
import systems.hugmesh.userbff.federation.FederationHttpClientSsl;

/**
 * Wires the {@link SessionsInternalClient}'s reactive {@link WebClient} to
 * hugmesh-admin-bff's internal session surface, REUSING the exact outbound patterns the
 * {@link systems.hugmesh.userbff.auth.AdminBffInternalConfig} established:
 *
 * <ul>
 *   <li>the mTLS connector of {@link FederationHttpClientSsl} — presents this BFF's
 *       cluster-CA client identity + trusts the cluster CA when
 *       {@code hugmesh.mtls.client.enabled=true} (default OFF ⇒ plain HTTP locally);
 *       and</li>
 *   <li>an outbound {@code X-Internal-Token} default header (header name
 *       {@code app.internal.token-header}, value {@code app.internal.token}) — the OUTBOUND
 *       counterpart to auth-core's INBOUND {@code InternalTokenWebFilter} on admin-bff.
 *       Stamped ONLY when the token is non-blank, so dev/test/CI (blank token) call without
 *       a header and admin-bff's filter is a matching no-op.</li>
 * </ul>
 *
 * <p>The {@code base-url} is the SAME {@code app.admin-bff.internal.base-url} the
 * {@code AdminBffInternalConfig} targets (admin-bff owns the {@code bff_session} table).
 *
 * <p>UNLIKE the OIDC-login internal client (which is a fail-closed STUB until
 * {@code app.bff.oidc.enabled} flips), session management is an ALWAYS-ON user feature, so
 * this client is built UNCONDITIONALLY. It degrades GRACEFULLY rather than fail-closed: a
 * "list my sessions" read is non-destructive, so when {@code app.sessions.management.enabled}
 * is off the client holds a {@code null} {@link WebClient} and the list resolves empty /
 * revoke no-ops (never a 500). The flag defaults ON so the feature is live in the
 * gateway-forwarded-JWT world today.
 */
@Configuration
public class SessionsInternalConfig {

    private static final Logger log = LoggerFactory.getLogger(SessionsInternalConfig.class);

    @Bean
    public SessionsInternalClient sessionsInternalClient(
            FederationHttpClientSsl mtls,
            @Value("${app.sessions.management.enabled:true}") boolean sessionsEnabled,
            @Value("${app.admin-bff.internal.base-url:http://snapdragon-admin-bff-api.snapdragon-backend.svc.cluster.local:8080}")
            String baseUrl,
            @Value("${app.internal.token-header:X-Internal-Token}") String tokenHeader,
            @Value("${app.internal.token:}") String internalToken) {

        if (!sessionsEnabled) {
            log.info("[admin-bff-sessions] session management disabled (app.sessions.management.enabled=false) — "
                    + "client ships as a graceful stub (empty list / no-op revoke)");
            return new SessionsInternalClient(null);
        }

        HttpClient httpClient = mtls.customize(HttpClient.create());
        WebClient.Builder builder = WebClient.builder()
                .baseUrl(baseUrl)
                .clientConnector(new ReactorClientHttpConnector(httpClient));
        if (internalToken != null && !internalToken.isBlank()) {
            builder.defaultHeader(tokenHeader, internalToken);
            log.info("[admin-bff-sessions] live client -> {} (X-Internal-Token stamp ON)", baseUrl);
        } else {
            // No internal token configured: admin-bff's inbound InternalTokenWebFilter is a
            // matching no-op when its own token is blank, so this is the dev/test/CI posture
            // — never an in-cluster posture (the deployment sets INTERNAL_TOKEN).
            log.warn("[admin-bff-sessions] live client -> {} but app.internal.token is BLANK — "
                    + "no X-Internal-Token stamp (expected only in dev/test/CI)", baseUrl);
        }
        return new SessionsInternalClient(builder.build());
    }
}
