package systems.hugmesh.userbff.federation;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.time.Instant;

/**
 * A "card" = one of the caller's OWN federation-bundle versions, as returned by
 * hugmesh-federation-api ({@code user_modules} table / {@code UserModule}). The
 * field names match the federation-api {@code UserModule} JSON FIELD-FOR-FIELD (its
 * getters serialize as {@code id, ownerUserId, slug, versionDir, contentHash,
 * manifestJson, visibility, createdAt, supersededAt}) so this client DTO binds the
 * upstream response directly.
 *
 * <p>{@code @JsonIgnoreProperties(ignoreUnknown = true)} keeps this resilient to
 * federation-api adding fields. A user only ever sees their own cards — the BFF
 * forwards the caller's JWT so federation-api scopes {@code /bundles/mine} to the
 * same subject.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record UserModuleCard(
        Long id,
        String ownerUserId,
        String slug,
        String versionDir,
        String contentHash,
        String manifestJson,
        String visibility,
        Instant createdAt,
        Instant supersededAt) {
}
