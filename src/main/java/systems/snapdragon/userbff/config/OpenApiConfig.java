package systems.snapdragon.userbff.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Minimal OpenAPI document metadata for the user BFF spec served by
 * springdoc-openapi-starter-webflux-ui at {@code /v3/api-docs}.
 *
 * <p>Sets a stable {@code info.title} (the service name) + {@code info.version} so
 * the generated artefacts downstream are sensibly named: the platform
 * ng-openapi-gen typed client for the paired snapdragon-user-ui and the docs
 * pipeline key off these fields. A programmatic {@link OpenAPI} bean is used
 * (rather than the {@code @OpenAPIDefinition} annotation) so the metadata is plain
 * bean wiring — no annotation reflection scan, which keeps the GraalVM native
 * build hint surface minimal.
 */
@Configuration(proxyBeanMethods = false)
public class OpenApiConfig {

    @Bean
    OpenAPI userBffOpenApi() {
        return new OpenAPI()
                .info(new Info()
                        .title("snapdragon-user-bff-api")
                        .version("0.1.0")
                        .description("User BFF API (/bff/user/**) — owner-scoped profile, "
                                + "home-guide preferences, federation-bundle cards, "
                                + "self-blocking, and instance-block recommendation. "
                                + "Every endpoint is keyed to the caller's Casdoor JWT subject."));
    }
}
