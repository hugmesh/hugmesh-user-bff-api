package systems.hugmesh.userbff.config;

import org.springframework.aot.hint.MemberCategory;
import org.springframework.aot.hint.RuntimeHints;
import org.springframework.aot.hint.RuntimeHintsRegistrar;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.ImportRuntimeHints;
import systems.hugmesh.userbff.block.UserBlock;
import systems.hugmesh.userbff.federation.FederationModerationModels;
import systems.hugmesh.userbff.federation.UserModuleCard;
import systems.hugmesh.userbff.media.MediaPoisonDecision;
import systems.hugmesh.userbff.media.PoisonModels;
import systems.hugmesh.userbff.meshdevice.InternalMeshDeviceController;
import systems.hugmesh.userbff.meshdevice.MeshDevice;
import systems.hugmesh.userbff.profile.UserProfile;
import systems.hugmesh.userbff.silence.SelfSilence;

/**
 * GraalVM native-image / AOT reachability hints for the bits the static
 * analyzer cannot see through on its own — mirrors hugmesh-admin-bff-api /
 * {@code NativeHintsConfig}.
 *
 * <p>Spring Boot's own AOT processing covers the framework surface (the WebFlux
 * WebClient codecs, the reactive OAuth2 resource-server JWT pipeline, R2DBC, and
 * the Jackson auto-configuration). What it cannot always infer:
 *
 * <ul>
 *   <li><b>JSON-bound DTOs</b> reached reflectively through Jackson — the records
 *       crossing the HTTP boundary ({@link UserProfile}, {@link UserBlock},
 *       {@link UserModuleCard}, the federation {@code SubmitRequest}). Casdoor /
 *       Matrix / Mastodon responses deserialize into raw {@code Map} (already
 *       reflection-safe), but the typed records need explicit binding hints so
 *       their canonical constructors/accessors survive native image.</li>
 *   <li><b>The springdoc Swagger UI webjar resources</b> — the
 *       {@code springdoc-openapi-starter-webflux-ui} starter serves the Swagger UI
 *       static assets out of {@code META-INF/resources/webjars/swagger-ui/}.
 *       native-image strips classpath resources by default, so the bundled assets
 *       404 without an explicit resource-include pattern. The raw {@code /v3/api-docs}
 *       JSON (what ng-openapi-gen + the docs pipeline actually consume) is produced
 *       by springdoc's own AOT-covered beans and does not need the webjar.</li>
 * </ul>
 *
 * <p>Best-effort: a full {@code -Pnative native:compile} on a GraalVM-equipped host
 * is the authoritative check; {@code add-reachability-metadata} (from the parent's
 * {@code native} profile) supplies the library-side metadata for the
 * WebClient/Netty/Jackson/r2dbc jars on top of these app-specific hints.
 */
@Configuration(proxyBeanMethods = false)
@ImportRuntimeHints(NativeHintsConfig.Hints.class)
public class NativeHintsConfig {

    static class Hints implements RuntimeHintsRegistrar {
        @Override
        public void registerHints(RuntimeHints hints, ClassLoader classLoader) {
            hints.reflection()
                    .registerType(UserProfile.class, dtoCategories())
                    .registerType(UserBlock.class, dtoCategories())
                    .registerType(UserModuleCard.class, dtoCategories())
                    .registerType(FederationModerationModels.SubmitRequest.class, dtoCategories())
                    .registerType(SelfSilence.class, dtoCategories())
                    // media-proxy DTOs: the server-owned decision + the worker-boundary
                    // records (health / poison result / survival verdict) crossing
                    // Jackson — explicit binding hints so they survive native image.
                    .registerType(MediaPoisonDecision.class, dtoCategories())
                    .registerType(PoisonModels.Health.class, dtoCategories())
                    .registerType(PoisonModels.PoisonResult.class, dtoCategories())
                    .registerType(PoisonModels.SizedBytes.class, dtoCategories())
                    .registerType(PoisonModels.SurvivalVerdict.class, dtoCategories())
                    // mesh-device DTOs: the owner-facing device record + the
                    // SERVICE-only bridge records (mapping row / batch status report)
                    // crossing Jackson — explicit binding hints so they survive
                    // native image.
                    .registerType(MeshDevice.class, dtoCategories())
                    .registerType(InternalMeshDeviceController.BridgeMapping.class, dtoCategories())
                    .registerType(InternalMeshDeviceController.StatusReport.class, dtoCategories());

            // Swagger UI static assets shipped inside the springdoc webflux-ui
            // starter's webjar. native-image drops classpath resources unless
            // explicitly included. The /v3/api-docs JSON is bean-produced and
            // unaffected, so the spec stays available regardless.
            hints.resources()
                    .registerPattern("META-INF/resources/webjars/swagger-ui/*")
                    .registerPattern("META-INF/resources/webjars/swagger-ui/**");
        }

        private static MemberCategory[] dtoCategories() {
            return new MemberCategory[] {
                    MemberCategory.INVOKE_DECLARED_CONSTRUCTORS,
                    MemberCategory.INVOKE_DECLARED_METHODS,
                    MemberCategory.DECLARED_FIELDS,
            };
        }
    }
}
