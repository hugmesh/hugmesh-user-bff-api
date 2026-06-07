package systems.snapdragon.userbff.block;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.snapdragon.userbff.federation.FederationApiClient;
import systems.snapdragon.userbff.web.ApiException;

import java.util.List;
import java.util.Map;

/**
 * Owner-enforced self-block operations. EVERY method takes the owner (the JWT
 * subject, from the validated token) and operates ONLY on that owner's blocks:
 *
 * <ul>
 *   <li>{@link #list(String)} returns only the owner's own blocks;</li>
 *   <li>{@link #block(String, String, String)} records a durable {@code user_block}
 *       row under the owner, THEN best-effort pushes the external mute/block to the
 *       matching platform client (Matrix/Mastodon; STUBBED by default) — the row is
 *       the source of truth even if the external push is stubbed/fails;</li>
 *   <li>{@link #unblock(String, String)} deletes only the owner's block (scoped by
 *       owner AND id);</li>
 *   <li>{@link #recommendInstanceBlock(String, String)} starts the recommend-
 *       instance-block chain by POSTing to federation-api (kind=instance-block,
 *       status set to 'recommended' server-side) — this is a RECOMMENDATION, not a
 *       self-block, and is gated to the caller's own forwarded JWT.</li>
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

    public Flux<UserBlock> list(String owner) {
        requireOwner(owner);
        return repo.listForOwner(owner);
    }

    /**
     * Record + push a self-block. The durable row is written FIRST (under the
     * owner), then the external push is best-effort (never fails the call). Returns
     * the persisted block with a {@code pushed} flag (whether a LIVE external call
     * ran vs. a documented stub).
     */
    public Mono<Map<String, Object>> block(String owner, String target, String platform) {
        requireOwner(owner);
        if (target == null || target.isBlank()) {
            return Mono.error(ApiException.badRequest("target required"));
        }
        String p = (platform == null || platform.isBlank()) ? "internal" : platform.trim();
        if (!UserBlock.validPlatform(p)) {
            return Mono.error(ApiException.badRequest("platform must be matrix|mastodon|internal"));
        }
        return repo.add(owner, target.trim(), p)
                .flatMap(saved -> pushExternal(owner, saved)
                        .map(pushed -> result(saved, pushed)));
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

    public Mono<Void> unblock(String owner, String id) {
        requireOwner(owner);
        return repo.delete(owner, id).flatMap(deleted -> deleted > 0
                ? Mono.empty()
                : Mono.error(ApiException.notFound("no such block for this user")));
    }

    /**
     * Start the recommend-instance-block chain via federation-api. The caller's JWT
     * is forwarded by the federation WebClient filter, so federation-api records the
     * recommendation under the caller as requester.
     */
    public Mono<Map<String, Object>> recommendInstanceBlock(String owner, String instance, String reason) {
        requireOwner(owner);
        if (instance == null || instance.isBlank()) {
            return Mono.error(ApiException.badRequest("instance required"));
        }
        return federation.recommendInstanceBlock(instance.trim(), reason)
                .map(resp -> Map.of("recommended", true, "instance", instance.trim(), "federation", resp));
    }

    private static Map<String, Object> result(UserBlock b, boolean pushed) {
        return Map.of("block", b, "pushed", pushed,
                "external", pushed ? "live" : ("internal".equals(b.platform()) ? "n/a" : "stubbed"));
    }

    private static void requireOwner(String owner) {
        if (owner == null || owner.isBlank()) {
            throw ApiException.unauthorized("missing authenticated subject");
        }
    }
}
