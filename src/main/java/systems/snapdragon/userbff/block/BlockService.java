package systems.snapdragon.userbff.block;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.snapdragon.userbff.federation.FederationApiClient;
import systems.snapdragon.commons.security.DomainRegistry;
import systems.snapdragon.commons.web.ApiException;

import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Owner-enforced self-block operations. EVERY method takes the owner (the JWT
 * subject, from the validated token) and operates ONLY on that owner's blocks:
 *
 * <ul>
 *   <li>{@link #list(String)} returns only the owner's own blocks;</li>
 *   <li>{@link #block(String, String, String, Set)} records a durable
 *       {@code user_block} row under the owner, THEN best-effort pushes the external
 *       mute/block to the matching platform client (Matrix/Mastodon; STUBBED by
 *       default) — the row is the source of truth even if the external push is
 *       stubbed/fails. PLATFORM-ROLE GATED (service leg / defence-in-depth): a
 *       {@code matrix} target requires {@code ROLE_MATRIX}, a {@code mastodon}
 *       target requires {@code ROLE_MASTODON}; the caller's authorities are passed
 *       in and re-checked here (the method-level {@code @PreAuthorize} on the
 *       controller is the API leg);</li>
 *   <li>{@link #unblock(String, String)} deletes only the owner's block (scoped by
 *       owner AND id);</li>
 *   <li>{@link #recommendInstanceBlock(String, String, Set)} starts the recommend-
 *       instance-block chain by POSTing to federation-api (kind=instance-block,
 *       status set to 'recommended' server-side) — this is a RECOMMENDATION, not a
 *       self-block, and is gated to the caller's own forwarded JWT. Requires a
 *       homeserver platform role ({@code ROLE_MATRIX} OR {@code ROLE_MASTODON}),
 *       re-checked here.</li>
 * </ul>
 */
@Service
public class BlockService {

    private static final Logger log = LoggerFactory.getLogger(BlockService.class);

    private final UserBlockRepository repo;
    private final Map<String, ExternalBlockClient> clientsByPlatform;
    private final FederationApiClient federation;

    public BlockService(UserBlockRepository repo,
                        List<ExternalBlockClient> clients,
                        FederationApiClient federation) {
        this.repo = repo;
        this.federation = federation;
        this.clientsByPlatform = new java.util.HashMap<>();
        for (ExternalBlockClient c : clients) this.clientsByPlatform.put(c.platform(), c);
    }

    /** Back-compat overload — scopes to the platform {@code default} domain. */
    public Flux<UserBlock> list(String owner) {
        return list(owner, DomainRegistry.DEFAULT_DOMAIN);
    }

    /** The owner's blocks within their DOMAIN. {@code domain} is the caller's
     *  validated-issuer brand (or {@code null} for the SUPERADMIN cross-domain
     *  bypass, which then sees every brand's rows). Owner-enforcement is UNWEAKENED —
     *  domain is an additional predicate. */
    public Flux<UserBlock> list(String owner, String domain) {
        requireOwner(owner);
        return repo.listForOwner(owner, domain);
    }

    /** Back-compat overload — stamps/operates on the platform {@code default} domain. */
    public Mono<Map<String, Object>> block(String owner, String target, String platform,
                                            Set<String> callerRoles) {
        return block(owner, target, platform, DomainRegistry.DEFAULT_DOMAIN, callerRoles);
    }

    /**
     * Record + push a self-block. The durable row is written FIRST (under the
     * owner), then the external push is best-effort (never fails the call). Returns
     * the persisted block with a {@code pushed} flag (whether a LIVE external call
     * ran vs. a documented stub).
     *
     * <p>PLATFORM-ROLE GATE (service leg): {@code matrix} needs {@code ROLE_MATRIX},
     * {@code mastodon} needs {@code ROLE_MASTODON} — re-checked from the caller's
     * forwarded authorities so the rule holds independently of the controller's
     * method-level {@code @PreAuthorize}. {@code internal} (the default) needs only
     * the ROLE_USER floor. A missing platform role is a 403.
     */
    public Mono<Map<String, Object>> block(String owner, String target, String platform,
                                            String domain, Set<String> callerRoles) {
        requireOwner(owner);
        if (target == null || target.isBlank()) {
            return Mono.error(ApiException.badRequest("target required"));
        }
        String p = (platform == null || platform.isBlank()) ? "internal" : platform.trim();
        if (!UserBlock.validPlatform(p)) {
            return Mono.error(ApiException.badRequest("platform must be matrix|mastodon|internal"));
        }
        ApiException forbidden = platformRoleForbidden(p, callerRoles);
        if (forbidden != null) {
            return Mono.error(forbidden);
        }
        // The row is stamped with the caller's DOMAIN (server-derived from the
        // validated issuer), so the block lands in the caller's own brand.
        return repo.add(owner, target.trim(), p, domain)
                .flatMap(saved -> pushExternal(owner, saved)
                        .map(pushed -> result(saved, pushed)));
    }

    /**
     * Service-leg platform-role guard (defence-in-depth, mirrors the controller's
     * method-level {@code @PreAuthorize}). Returns a 403 {@link ApiException} when
     * the caller lacks the access role required to act on the platform's homeserver,
     * else {@code null}:
     * <ul>
     *   <li>{@code matrix}   -> requires {@code ROLE_MATRIX};</li>
     *   <li>{@code mastodon} -> requires {@code ROLE_MASTODON};</li>
     *   <li>{@code internal} (and any non-homeserver value) -> no platform role.</li>
     * </ul>
     */
    private static ApiException platformRoleForbidden(String platform, Set<String> callerRoles) {
        Set<String> roles = callerRoles == null ? Set.of() : callerRoles;
        if ("matrix".equals(platform) && !roles.contains("ROLE_MATRIX")) {
            return ApiException.forbidden("ROLE_MATRIX required to block on matrix");
        }
        if ("mastodon".equals(platform) && !roles.contains("ROLE_MASTODON")) {
            return ApiException.forbidden("ROLE_MASTODON required to block on mastodon");
        }
        return null;
    }

    private Mono<Boolean> pushExternal(String owner, UserBlock saved) {
        ExternalBlockClient client = clientsByPlatform.get(saved.platform());
        if (client == null) return Mono.just(false);   // 'internal' — no external push
        return client.block(owner, saved.target())
                .onErrorResume(e -> {
                    log.warn("[block] best-effort {} push for {} failed (row kept): {}",
                            saved.platform(), saved.target(), e.toString());
                    return Mono.just(false);
                });
    }

    /** Back-compat overload — scopes to the platform {@code default} domain. */
    public Mono<Void> unblock(String owner, String id) {
        return unblock(owner, id, DomainRegistry.DEFAULT_DOMAIN);
    }

    public Mono<Void> unblock(String owner, String id, String domain) {
        requireOwner(owner);
        return repo.delete(owner, id, domain).flatMap(deleted -> deleted > 0
                ? Mono.empty()
                : Mono.error(ApiException.notFound("no such block for this user")));
    }

    /**
     * Start the recommend-instance-block chain via federation-api. The caller's JWT
     * is forwarded by the federation WebClient filter, so federation-api records the
     * recommendation under the caller as requester.
     *
     * <p>Requires a homeserver platform role ({@code ROLE_MATRIX} OR
     * {@code ROLE_MASTODON}) — re-checked here (service leg) as defence-in-depth on
     * top of the controller's method-level {@code @PreAuthorize}. Only a platform
     * participant recommends an instance block.
     */
    public Mono<Map<String, Object>> recommendInstanceBlock(String owner, String instance, String reason,
                                                            Set<String> callerRoles) {
        requireOwner(owner);
        Set<String> roles = callerRoles == null ? Set.of() : callerRoles;
        if (!roles.contains("ROLE_MATRIX") && !roles.contains("ROLE_MASTODON")) {
            return Mono.error(ApiException.forbidden(
                    "a platform role (ROLE_MATRIX or ROLE_MASTODON) is required to recommend an instance block"));
        }
        if (instance == null || instance.isBlank()) {
            return Mono.error(ApiException.badRequest("instance required"));
        }
        return federation.recommendInstanceBlock(instance.trim(), reason)
                .map(resp -> Map.of("recommended", true, "instance", instance.trim(), "federation", resp));
    }

    private static Map<String, Object> result(UserBlock b, boolean pushed) {
        return Map.of("block", b, "pushed", pushed,
                "external", pushed ? "live" : "internal".equals(b.platform()) ? "n/a" : "stubbed");
    }

    private static void requireOwner(String owner) {
        if (owner == null || owner.isBlank()) {
            throw ApiException.unauthorized("missing authenticated subject");
        }
    }
}
