package systems.snapdragon.userbff.prefstore;

import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import systems.snapdragon.userbff.media.MediaPoisonDecision;
import systems.snapdragon.userbff.media.MediaPoisoningProperties;
import systems.snapdragon.commons.security.DomainRegistry;
import systems.snapdragon.commons.web.ApiException;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Owner-enforced DURABLE per-user UI preferences. The compose surfaces (the
 * mastodon/matrix AI-poison toggle) and other UI-wave preference toggles read the
 * resolved view via {@link #get} and persist a change via {@link #put}. EVERY method
 * takes the owner (the JWT subject) and operates ONLY on that owner's preferences in
 * that owner's domain — a user can never read/write another user's (or brand's)
 * preferences.
 *
 * <p>Resolution is DEFAULTS-MERGED: {@link #get} returns the server default for any
 * preference the user has not explicitly set, so the UI always renders a complete,
 * honest toggle state. The headline preference is {@link #MEDIA_POISON_DEFAULT} — the
 * per-user durable AI-poison default whose fallback MIRRORS the server
 * {@link MediaPoisoningProperties#getDefaultMode()} (so an unset user inherits the
 * operator policy; once set, the user's durable choice wins).
 */
@Service
public class UserPreferencesService {

    /** The per-user durable AI-poison default the compose toggle persists. Unset =>
     *  inherit the server {@link MediaPoisoningProperties#getDefaultMode()}. */
    public static final String MEDIA_POISON_DEFAULT = "media.poison.default";

    private final UserPreferencesStoreRepository repo;
    private final MediaPoisoningProperties mediaProps;

    public UserPreferencesService(UserPreferencesStoreRepository repo,
                                  MediaPoisoningProperties mediaProps) {
        this.repo = repo;
        this.mediaProps = mediaProps;
    }

    /** Back-compat overload — scopes to the platform {@code default} domain. */
    public Mono<Map<String, String>> get(String owner) {
        return get(owner, DomainRegistry.DEFAULT_DOMAIN);
    }

    /**
     * The owner's resolved preferences in their domain: every stored value, with the
     * server default merged in for any unset known preference (so the toggle state is
     * always complete). {@code domain} null = SUPERADMIN cross-domain bypass.
     */
    public Mono<Map<String, String>> get(String owner, String domain) {
        requireOwner(owner);
        return repo.findAll(owner, domain).map(stored -> {
            Map<String, String> out = new LinkedHashMap<>(defaults());
            // the user's explicit, durable choices override the server defaults.
            out.putAll(stored);
            return out;
        });
    }

    /** Back-compat overload — operates on the platform {@code default} domain. */
    public Mono<Map<String, String>> put(String owner, String key, String value) {
        return put(owner, key, value, DomainRegistry.DEFAULT_DOMAIN);
    }

    /**
     * Upsert ONE durable preference for the owner in their domain, then return the
     * resolved view. The key is validated against the known-preference vocabulary and
     * the value against that preference's allowed values (the AI-poison default must
     * be a valid cloak mode) so a client can never persist a key/value the UI can't
     * honour. {@code domain} null = SUPERADMIN cross-domain bypass.
     */
    public Mono<Map<String, String>> put(String owner, String key, String value, String domain) {
        requireOwner(owner);
        String k = key == null ? "" : key.trim();
        if (!isKnownKey(k)) {
            return Mono.error(ApiException.badRequest("unknown preference key"));
        }
        String v = normalizeValue(k, value);
        return repo.upsert(owner, k, v, domain).then(get(owner, domain));
    }

    /** The server-default view (no user rows) — every known preference at its server
     *  default. The AI-poison default MIRRORS the server media poisoning policy. */
    Map<String, String> defaults() {
        Map<String, String> d = new LinkedHashMap<>();
        d.put(MEDIA_POISON_DEFAULT, mediaProps.getDefaultMode());
        return d;
    }

    /** True iff {@code key} is a preference this BFF recognises (fail-closed on
     *  anything else so the durable store can't be turned into arbitrary storage). */
    static boolean isKnownKey(String key) {
        return MEDIA_POISON_DEFAULT.equals(key);
    }

    /** Validate + canonicalise a value for the given known key. The AI-poison default
     *  must be one of the cloak modes ({@code glaze|nightshade|light|none}); reject
     *  anything else as a clean 400 so a bad value never reaches the durable row. */
    private static String normalizeValue(String key, String rawValue) {
        String v = rawValue == null ? "" : rawValue.trim();
        if (MEDIA_POISON_DEFAULT.equals(key)) {
            String mode = v.toLowerCase();
            if (!MediaPoisonDecision.validMode(mode)) {
                throw ApiException.badRequest("media.poison.default must be glaze|nightshade|light|none");
            }
            return mode;
        }
        return v;
    }

    private static void requireOwner(String owner) {
        if (owner == null || owner.isBlank()) {
            throw ApiException.unauthorized("missing authenticated subject");
        }
    }
}
