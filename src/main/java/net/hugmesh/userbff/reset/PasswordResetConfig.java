package net.hugmesh.userbff.reset;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.client.WebClient;

import java.util.Base64;

/**
 * Wires the reactive {@link CasdoorPasswordResetClient} for the ANONYMOUS
 * forgot-password flow. Two mutually-exclusive beans on
 * {@code casdoor.password-reset.enabled}, mirroring {@code CasdoorUserConfig}:
 *
 * <ul>
 *   <li>{@code true} → a real {@link WebClient} (Basic client-credentials) pointed at
 *       the INTERNAL Casdoor;</li>
 *   <li>otherwise (DEFAULT) → a {@code null} WebClient, i.e. the surface is DARK and
 *       every call fails closed with a 503.</li>
 * </ul>
 *
 * <p><b>Why a SEPARATE flag from {@code casdoor.account.enabled}.</b> The account flag
 * governs an AUTHENTICATED surface whose worst case is a stubbed no-op visible in the
 * response. This flag governs a PERMITALL, credential-WRITING surface whose live path
 * mails a code and then rotates a password on a bare username. Those two deserve
 * independent decisions: an operator who has enabled self-service password CHANGE has
 * not thereby consented to expose an anonymous reset, and — critically — the reset is
 * useless until Casdoor SMTP is provisioned, which is a separate deployment act again
 * (hugmesh-generator {@code manifests/casdoor/app-conf-configmap.yaml} leaves the SMTP
 * env vars unset when {@code secret/<brand>/mail} is absent). One flag would have forced
 * a live-but-undeliverable reset on every mesh that already had account writes on.
 *
 * <p>Credentials are reused from {@code casdoor.account.*} rather than re-declared: it
 * is the SAME Casdoor application principal, and a second copy of a client secret is a
 * second thing to rotate and to get wrong.
 */
@Configuration
public class PasswordResetConfig {

    @Bean
    @ConditionalOnProperty(name = "casdoor.password-reset.enabled", havingValue = "true")
    public CasdoorPasswordResetClient liveCasdoorPasswordResetClient(
            @Value("${casdoor.account.base-url:${casdoor.gateway-base:http://casdoor.hugmesh-pki.svc.cluster.local:8000}}") String baseUrl,
            @Value("${casdoor.account.client-id:app-user-bff}") String clientId,
            @Value("${casdoor.account.client-secret:}") String clientSecret,
            @Value("${casdoor.organization:hugmesh}") String organization,
            @Value("${casdoor.password-reset.application-id:admin/app-user-bff}") String applicationId) {
        WebClient web = WebClient.builder()
                .baseUrl(baseUrl)
                .defaultHeader("Authorization", "Basic "
                        + Base64.getEncoder().encodeToString((clientId + ":" + clientSecret).getBytes()))
                .build();
        return new CasdoorPasswordResetClient(web, organization, applicationId);
    }

    @Bean
    @ConditionalOnProperty(name = "casdoor.password-reset.enabled", havingValue = "false",
            matchIfMissing = true)
    public CasdoorPasswordResetClient darkCasdoorPasswordResetClient(
            @Value("${casdoor.organization:hugmesh}") String organization,
            @Value("${casdoor.password-reset.application-id:admin/app-user-bff}") String applicationId) {
        return new CasdoorPasswordResetClient(null, organization, applicationId);
    }
}
