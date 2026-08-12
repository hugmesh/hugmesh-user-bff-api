package net.hugmesh.userbff.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.media.StringSchema;
import io.swagger.v3.oas.models.servers.Server;
import org.springdoc.core.customizers.OpenApiCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

/**
 * Minimal OpenAPI document metadata for the user BFF spec served by
 * springdoc-openapi-starter-webflux-ui at {@code /v3/api-docs}.
 *
 * <p>Sets a stable {@code info.title} (the service name) + {@code info.version} so
 * the generated artefacts downstream are sensibly named: the platform
 * ng-openapi-gen typed client for the paired hugmesh-user-ui and the docs
 * pipeline key off these fields. A programmatic {@link OpenAPI} bean is used
 * (rather than the {@code @OpenAPIDefinition} annotation) so the metadata is plain
 * bean wiring — no annotation reflection scan, which keeps the GraalVM native
 * build hint surface minimal.
 *
 * <p>A single relative {@code ""} server is pinned so the spec is DETERMINISTIC: under
 * Spring Boot 4 / springdoc-3.1, the auto-derived "Generated server url" otherwise
 * resolves to the live (random) port when the spec is dumped from a RANDOM_PORT test,
 * which would make the committed openapi.json non-byte-stable across runs. The relative
 * server keeps every path resolving against whatever host the UI/docs pipeline reads the
 * committed spec from.
 */
@Configuration(proxyBeanMethods = false)
public class OpenApiConfig {

    @Bean
    OpenAPI userBffOpenApi() {
        return new OpenAPI()
                .servers(List.of(new Server().url("")))
                .info(new Info()
                        .title("hugmesh-user-bff-api")
                        .version("0.2.0")
                        .description("User BFF API (/bff/user/**) — every endpoint is "
                                + "owner-scoped to the caller's Casdoor JWT subject. "
                                + "Surfaces: native login/register/session, own-profile "
                                + "CRUD + avatar upload, Casdoor password/email relays, "
                                + "the durable per-user preference store "
                                + "(media.poison.default + mastodon.appearance.*), "
                                + "per-category notification preferences, the in-app "
                                + "notification inbox + SSE stream, home-guide "
                                + "dismissal, self-blocks + instance-block "
                                + "recommendation, self-silence, login-session list/"
                                + "revoke, connected apps & devices, federation cards, "
                                + "the media AI-cloak proxy, Meshtastic mesh-device "
                                + "claims, VN character parts + expression stickers, "
                                + "account status, and the Matrix/Mastodon reverse "
                                + "proxies."));
    }

    /**
     * Post-scan export of the BFF-owned {@code MediaPoisonMode} contract enum for the
     * durable {@code media.poison.default} preference value. The PUT body's generic
     * {@code {key,value}} shape cannot carry a per-key enum, so the vocabulary is
     * exported as an explicit component schema — ng-openapi-gen emits a typed
     * {@code MediaPoisonMode} for UI clients to import, pinning the UI union to the
     * server's (the vocabulary-drift class of bug this closes).
     *
     * <p>MUST be an {@link OpenApiCustomizer} (runs AFTER springdoc's controller scan),
     * NOT a {@code Components} set on the {@link OpenAPI} bean above: springdoc replaces
     * the base bean's components with its scanned model schemas, so a schema registered
     * there is silently dropped from the served/dumped document (verified against the
     * regenerated spec — {@code OpenApiSpecDumpTest} now asserts the schema survives).
     */
    @Bean
    OpenApiCustomizer mediaPoisonModeSchemaCustomizer() {
        return openApi -> {
            if (openApi.getComponents() == null) {
                openApi.setComponents(new Components());
            }
            openApi.getComponents().addSchemas("MediaPoisonMode", mediaPoisonModeSchema());
        };
    }

    /** The exported {@code MediaPoisonMode} schema — the user-facing AI-cloak vocabulary
     *  {@code off|low|medium|high} (kept in lockstep with the BFF-owned
     *  {@code net.hugmesh.userbff.prefstore.MediaPoisonMode} enum). */
    private static StringSchema mediaPoisonModeSchema() {
        StringSchema schema = new StringSchema();
        schema._enum(List.of("off", "low", "medium", "high"));
        schema.setDescription("User-facing AI-cloak intensity for the "
                + "media.poison.default preference (BFF-owned "
                + "vocabulary; the source of truth for UI "
                + "clients): off = no cloaking, low = subtle, "
                + "medium = recommended default, high = "
                + "aggressive. Maps server-side onto the engine "
                + "cloak modes none|light|glaze|nightshade.");
        return schema;
    }
}
