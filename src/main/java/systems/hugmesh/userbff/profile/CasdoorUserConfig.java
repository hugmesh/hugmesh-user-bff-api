package systems.hugmesh.userbff.profile;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.client.WebClient;

import java.util.Base64;

/**
 * Wires the reactive {@link CasdoorUserClient} for self-service password/email
 * changes. Two beans, both always present so the {@code ProfileService} flow is
 * always wired:
 *
 * <ul>
 *   <li>when {@code casdoor.account.enabled=true} the client carries a real
 *       {@link WebClient} (Basic client-credentials) pointed at Casdoor;</li>
 *   <li>otherwise (default) the client is constructed with a {@code null}
 *       WebClient — every call is a documented no-op STUB (the reactive flow runs
 *       end-to-end, no Casdoor write).</li>
 * </ul>
 *
 * The {@code @ConditionalOnProperty} pair is mutually exclusive on the flag.
 */
@Configuration
public class CasdoorUserConfig {

    @Bean
    @ConditionalOnProperty(name = "casdoor.account.enabled", havingValue = "true")
    public CasdoorUserClient liveCasdoorUserClient(
            @Value("${casdoor.account.base-url:${casdoor.gateway-base:http://casdoor.hugmesh-pki.svc.cluster.local:8000}}") String baseUrl,
            @Value("${casdoor.account.client-id:app-user-bff}") String clientId,
            @Value("${casdoor.account.client-secret:}") String clientSecret,
            @Value("${casdoor.organization:hugmesh}") String organization) {
        WebClient web = WebClient.builder()
                .baseUrl(baseUrl)
                .defaultHeader("Authorization", "Basic "
                        + Base64.getEncoder().encodeToString((clientId + ":" + clientSecret).getBytes()))
                .build();
        return new CasdoorUserClient(web, organization);
    }

    @Bean
    @ConditionalOnProperty(name = "casdoor.account.enabled", havingValue = "false", matchIfMissing = true)
    public CasdoorUserClient stubCasdoorUserClient(
            @Value("${casdoor.organization:hugmesh}") String organization) {
        return new CasdoorUserClient(null, organization);
    }
}
