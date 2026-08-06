package systems.hugmesh.userbff.character;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import systems.hugmesh.userbff.auth.CanonicalIdentityResolver;
import systems.hugmesh.userbff.hsproxy.HsServiceTokenRow;
import systems.hugmesh.userbff.hsproxy.HsTokenCustody;
import systems.hugmesh.userbff.hsproxy.ServiceTokenBroker;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Registers an owner's ACTIVE VN-character expression stickers as a server-side MSC2545
 * sticker pack -- the {@code im.ponies.user_emotes} entry in the owner's Matrix
 * account-data -- so Matrix clients show them in the sticker picker. This is the SERVER
 * (registration) half ONLY: the {@code m.sticker} SEND stays client-side (the BFF has no
 * roomId source), so there is NO send/roomId endpoint here.
 *
 * <p>CONTEXT: this runs under the {@code ROLE_SERVICE} principal off the moderation
 * activation loop ({@link CharacterModerationService#resolveSticker} ACTIVE branch) -- there
 * is NO user JWT, so EVERYTHING is resolved from the OWNER SUBJECT carried on the post-flip
 * {@link VnSticker}, never a bearer.
 *
 * <p>FLOW (all fail-soft -- a homeserver outage NEVER fails the moderator's activation):
 * <ol>
 *   <li>load the owner's decrypted Matrix custody token ({@link HsTokenCustody#loadAccessToken});
 *       on empty, re-mint once via {@link ServiceTokenBroker#mintMatrix} (mirrors the
 *       HsReverseProxy re-mint pattern). Still empty =&gt; no-op (nothing to authorise with);</li>
 *   <li>resolve the FULL Matrix user id {@code @localpart:server} from the custody row's
 *       localpart + the configured homeserver name;</li>
 *   <li>READ-MODIFY-WRITE: GET the current {@code im.ponies.user_emotes}, MERGE the owner's
 *       ACTIVE stickers into it WITHOUT clobbering any non-VN emotes already present, PUT
 *       the merged object back.</li>
 * </ol>
 *
 * <p>MSC2545 content shape written:
 * <pre>{@code
 * {
 *   "pack":   {"display_name": "<owner> stickers", "usage": ["sticker"]},
 *   "images": {"<expression>": {"url": "mxc://...", "body": "<expression>", "usage": ["sticker"]}, ...}
 * }
 * }</pre>
 */
@Service
public class StickerPackRegistrationService {

    private static final Logger log = LoggerFactory.getLogger(StickerPackRegistrationService.class);

    /** The MSC2545 user-emotes account-data type. */
    static final String EMOTES_TYPE = "im.ponies.user_emotes";
    /** MSC2545 keys. */
    static final String K_PACK = "pack";
    static final String K_IMAGES = "images";
    static final String K_DISPLAY_NAME = "display_name";
    static final String K_USAGE = "usage";
    static final String K_URL = "url";
    static final String K_BODY = "body";
    /** The single usage marker for sticker-only packs. */
    static final List<String> USAGE_STICKER = List.of("sticker");

    private final VnStickerRepository stickerRepo;
    private final HsTokenCustody custody;
    private final ServiceTokenBroker broker;
    private final MatrixClientApiClient matrix;
    private final CanonicalIdentityResolver identity;
    /** The homeserver name = the {@code :server} part of {@code @localpart:server}. */
    private final String serverName;
    /**
     * DARK-BY-DEFAULT master switch. FALSE (the default) =&gt; the whole feature is inert: the
     * very first check in {@link #registerActivePack(String)} short-circuits to a no-op
     * BEFORE any cipher / custody / Matrix work, so dev + CI run as if the feature did not
     * exist. Flip to {@code true} (alongside the live {@link MatrixClientApiClient} wiring)
     * only once per-user homeserver-token brokering is validated against a real homeserver.
     */
    private final boolean enabled;

    public StickerPackRegistrationService(
            VnStickerRepository stickerRepo,
            HsTokenCustody custody,
            ServiceTokenBroker broker,
            MatrixClientApiClient matrix,
            CanonicalIdentityResolver identity,
            @Value("${sticker.matrix.register.enabled:false}") boolean enabled,
            @Value("${sticker.matrix.server-name:${MATRIX_SERVER_NAME:hugmesh.systems}}")
            String serverName) {
        this.stickerRepo = stickerRepo;
        this.custody = custody;
        this.broker = broker;
        this.matrix = matrix;
        this.identity = identity;
        this.enabled = enabled;
        this.serverName = serverName;
    }

    /**
     * Upsert {@code ownerSubject}'s ACTIVE sticker set into their Matrix
     * {@code im.ponies.user_emotes} account-data. BEST-EFFORT + FAIL-SOFT throughout -- the
     * caller hooks this onto a successful activation and swallows any error, so a homeserver
     * outage never fails the moderator's flip. A no-op (completes empty) when: the cipher is
     * unavailable; no custody token can be loaded OR minted; or (dark mode) the live client
     * is stubbed and there is no token.
     */
    public Mono<Void> registerActivePack(String ownerSubject) {
        if (!enabled) {
            // DARK-BY-DEFAULT: the master switch is off -- short-circuit BEFORE any cipher /
            // custody / Matrix work so dev + CI are wholly inert (the feature ships dark).
            return Mono.empty();
        }
        if (ownerSubject == null || ownerSubject.isBlank()) {
            return Mono.empty();
        }
        if (!custody.cipherAvailable()) {
            // No at-rest key => no decryptable token => nothing to authorise with. No-op.
            log.info("[sticker-pack] cipher unavailable -- skip pack registration for owner={}", ownerSubject);
            return Mono.empty();
        }
        // Resolve the custody ROW first (it carries the localpart we need for the user id),
        // then the decrypted token (load, else re-mint once). Both owner-scoped.
        return custody.findRow(ownerSubject, HsServiceTokenRow.PLATFORM_MATRIX)
                .flatMap(row -> tokenFor(ownerSubject, row.localpart())
                        .flatMap(token -> registerWith(ownerSubject, row.localpart(), token)))
                // No custody row at all -> try a fresh mint (which creates one), then register.
                .switchIfEmpty(mintThenRegister(ownerSubject))
                .onErrorResume(e -> {
                    // Activation must NEVER fail on a registration error.
                    log.warn("[sticker-pack] registration failed for owner={} (swallowed): {}",
                            ownerSubject, e.toString());
                    return Mono.empty();
                });
    }

    /** Load the decrypted token; on empty re-mint once (mirrors the proxy re-mint pattern). */
    private Mono<String> tokenFor(String ownerSubject, String localpart) {
        return custody.loadAccessToken(ownerSubject, HsServiceTokenRow.PLATFORM_MATRIX)
                .switchIfEmpty(Mono.defer(() -> broker.mintMatrix(ownerSubject, localpart)
                        .map(minted -> minted.accessToken())));
    }

    /**
     * No custody row yet: resolve the CANONICAL, persisted mint candidate, mint (creates the row
     * + localpart), then register with that token.
     *
     * <p>Resolves the PERSISTED, collision-checked {@code account.localpart} (admin-bff Liquibase
     * changeset 290) for the owner's OWN account via the shared {@link CanonicalIdentityResolver}
     * ({@link CanonicalIdentityResolver#ownMatrixLocalpartForSubject}) -- the SAME
     * account-takeover-by-collision fix the proxy/media mint sites apply. FAIL CLOSED: when no
     * canonical localpart can be resolved (no such account, a blank localpart, or an admin-bff
     * failure) this completes EMPTY, so NOTHING is minted or registered. The OLD behaviour here
     * ({@link ServiceTokenBroker#localpart}-sanitizing the raw {@code ownerSubject}) was the exact
     * unchecked-candidate takeover bug -- two different accounts can derive the SAME sanitized
     * candidate from unrelated subjects -- and is deliberately GONE. The class stays fail-soft
     * overall (a no-op never fails the moderator's activation), so failing closed here only means
     * "no sticker pack registered", never a failed flip.
     */
    private Mono<Void> mintThenRegister(String ownerSubject) {
        return Mono.defer(() -> identity.ownMatrixLocalpartForSubject(ownerSubject)
                .flatMap(candidate -> broker.mintMatrix(ownerSubject, candidate))
                .flatMap(minted -> registerWith(ownerSubject, minted.localpart(), minted.accessToken())));
    }

    /** With a localpart + token in hand: build the user id, read-modify-write the pack. */
    private Mono<Void> registerWith(String ownerSubject, String localpart, String token) {
        if (token == null || token.isBlank()) {
            log.info("[sticker-pack] no Matrix token for owner={} -- skip pack registration", ownerSubject);
            return Mono.empty();
        }
        String userId = matrixUserId(localpart);
        return stickerRepo.listActiveForOwner(ownerSubject)
                .collectList()
                .flatMap(active -> readModifyWrite(ownerSubject, userId, active, token));
    }

    /**
     * READ-MODIFY-WRITE: GET the current pack, MERGE the VN stickers in (without clobbering
     * any pre-existing non-VN emotes), PUT it back. A GET miss (no pack yet, stub mode, or a
     * fail-soft empty) starts from an empty object.
     */
    private Mono<Void> readModifyWrite(String ownerSubject, String userId,
                                       List<VnSticker> active, String token) {
        return matrix.getAccountData(userId, EMOTES_TYPE, token)
                .defaultIfEmpty(new LinkedHashMap<>())
                .flatMap(existing -> {
                    Map<String, Object> merged = mergePack(ownerSubject, existing, active);
                    return matrix.setAccountData(userId, EMOTES_TYPE, merged, token)
                            .doOnSuccess(v -> log.info(
                                    "[sticker-pack] registered {} active sticker(s) for owner={} userId={}",
                                    active.size(), ownerSubject, userId));
                });
    }

    /**
     * Merge the owner's ACTIVE stickers into the EXISTING account-data object as MSC2545
     * images, de-duplicating by expression (newest-first list =&gt; the FIRST occurrence of an
     * expression wins). The merge:
     * <ul>
     *   <li>PRESERVES every existing {@code images.*} entry that the VN set does not replace
     *       (so non-VN / hand-curated emotes are never clobbered) -- a VN expression key DOES
     *       overwrite a stale same-key entry (re-registration converges to the live mxc);</li>
     *   <li>sets/refreshes the {@code pack} block (display name + sticker usage) without
     *       dropping any other pack metadata the user may have set.</li>
     * </ul>
     * Returns a NEW object (the existing map is not mutated in place beyond defensive copies).
     */
    @SuppressWarnings("unchecked")
    static Map<String, Object> mergePack(String ownerSubject, Map<String, Object> existing,
                                         List<VnSticker> active) {
        Map<String, Object> result = new LinkedHashMap<>(
                existing == null ? Map.of() : existing);

        // -- images: copy the existing object, then layer the VN stickers on top --
        Map<String, Object> images = new LinkedHashMap<>();
        Object existingImages = result.get(K_IMAGES);
        if (existingImages instanceof Map<?, ?> em) {
            em.forEach((k, v) -> images.put(String.valueOf(k), v));
        }
        // De-dup by expression: the list is newest-first, so the FIRST occurrence of an
        // expression is the newest mxc -- a later (older) row for the same expression is
        // skipped (a 'seen' set, not a re-overwrite, so the newest never gets clobbered).
        java.util.Set<String> placed = new java.util.HashSet<>();
        for (VnSticker s : active) {
            String expr = s.expression();
            if (expr == null || expr.isBlank() || s.mxcUrl() == null || s.mxcUrl().isBlank()) {
                continue; // skip malformed rows (defence-in-depth)
            }
            if (!placed.add(expr)) {
                continue; // an older row for this expression already won -- keep the newest
            }
            Map<String, Object> img = new LinkedHashMap<>();
            img.put(K_URL, s.mxcUrl());
            img.put(K_BODY, expr);
            img.put(K_USAGE, new ArrayList<>(USAGE_STICKER));
            images.put(expr, img); // overwrites only a stale same-key entry; non-VN keys untouched
        }
        result.put(K_IMAGES, images);

        // -- pack: preserve other pack metadata, set display_name + sticker usage --
        Map<String, Object> pack = new LinkedHashMap<>();
        Object existingPack = result.get(K_PACK);
        if (existingPack instanceof Map<?, ?> ep) {
            ep.forEach((k, v) -> pack.put(String.valueOf(k), v));
        }
        pack.put(K_DISPLAY_NAME, displayName(ownerSubject));
        pack.put(K_USAGE, new ArrayList<>(USAGE_STICKER));
        result.put(K_PACK, pack);

        return result;
    }

    /** The full Matrix user id {@code @localpart:server} from the localpart + homeserver name. */
    private String matrixUserId(String localpart) {
        String lp = (localpart == null || localpart.isBlank())
                ? "user" : ServiceTokenBroker.localpart(localpart);
        return "@" + lp + ":" + serverName;
    }

    /** Human-readable pack display name derived from the owner subject (no PII leak beyond
     *  the subject the owner already holds). */
    private static String displayName(String ownerSubject) {
        return ServiceTokenBroker.localpart(ownerSubject) + " stickers";
    }
}
