package systems.hugmesh.userbff.prefstore;

import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import systems.hugmesh.userbff.media.MediaPoisoningProperties;
import systems.hugmesh.commons.security.DomainRegistry;
import systems.hugmesh.commons.web.ApiException;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/**
 * Owner-enforced DURABLE per-user UI preferences. The compose surfaces (the
 * mastodon/matrix AI-poison toggle), the mastodon-ui appearance panel
 * ({@code PreferencesService} — theme/accent/layout/density/etc, see
 * {@link #APPEARANCE_KEYS}), and other UI-wave preference toggles read the resolved
 * view via {@link #get} and persist a change via {@link #put}. EVERY method takes the
 * owner (the JWT subject) and operates ONLY on that owner's preferences in that
 * owner's domain — a user can never read/write another user's (or brand's)
 * preferences.
 *
 * <p>Resolution is DEFAULTS-MERGED for keys that have a SERVER-known default (today
 * only {@link #MEDIA_POISON_DEFAULT}, mirroring {@link MediaPoisoningProperties}): an
 * unset user inherits the server default so the UI always renders a complete, honest
 * toggle state. The appearance keys have NO server-side default opinion — the
 * platform-wide fallback for those lives in the admin-bff
 * {@code mastodon/appearance-default} endpoint, with the client's built-in default as
 * the final fallback — so {@link #get} returns an appearance key ONLY when the user
 * has explicitly set it (its ABSENCE from the resolved view is itself meaningful:
 * "this user has not customised this field").
 */
@Service
public class UserPreferencesService {

    /** The per-user durable AI-poison default the preferences panel persists. Unset =>
     *  inherit the server {@link MediaPoisoningProperties#getDefaultMode()} (an ENGINE
     *  token, translated to the user-facing {@link MediaPoisonMode} vocabulary on the
     *  defaults merge). Wire vocabulary: {@code off|low|medium|high} — the BFF-owned
     *  contract the paired hugmesh-user-ui panel speaks. */
    public static final String MEDIA_POISON_DEFAULT = "media.poison.default";

    // ── mastodon-ui appearance preferences (PreferencesService.AppearancePreferences) ──
    // One durable key per field, dotted under "mastodon.appearance." so the vocabulary
    // stays namespaced from any other remote's future preference keys. Field names
    // mirror the TS AppearancePreferences interface exactly.
    public static final String APPEARANCE_THEME = "mastodon.appearance.theme";
    public static final String APPEARANCE_ACCENT = "mastodon.appearance.accent";
    public static final String APPEARANCE_APPEARANCE = "mastodon.appearance.appearance";
    public static final String APPEARANCE_LAYOUT = "mastodon.appearance.layout";
    public static final String APPEARANCE_DENSITY = "mastodon.appearance.density";
    public static final String APPEARANCE_MEDIA_CORNERS = "mastodon.appearance.mediaCorners";
    public static final String APPEARANCE_FONT = "mastodon.appearance.font";
    public static final String APPEARANCE_TEXT_SIZE = "mastodon.appearance.textSize";
    public static final String APPEARANCE_HIGH_CONTRAST = "mastodon.appearance.highContrast";
    public static final String APPEARANCE_REDUCED_MOTION = "mastodon.appearance.reducedMotion";

    /** Every durable appearance key this BFF recognises. */
    public static final Set<String> APPEARANCE_KEYS = Set.of(
            APPEARANCE_THEME, APPEARANCE_ACCENT, APPEARANCE_APPEARANCE, APPEARANCE_LAYOUT,
            APPEARANCE_DENSITY, APPEARANCE_MEDIA_CORNERS, APPEARANCE_FONT, APPEARANCE_TEXT_SIZE,
            APPEARANCE_HIGH_CONTRAST, APPEARANCE_REDUCED_MOTION);

    private static final Set<String> THEME_VALUES =
            Set.of("snap-neon", "pastel-rose", "pastel-sky", "pastel-mint", "mono");
    private static final Set<String> ACCENT_VALUES =
            Set.of("neon", "rose", "lavender", "sky", "mint", "peach");
    private static final Set<String> APPEARANCE_MODE_VALUES = Set.of("auto", "light", "dark");
    private static final Set<String> LAYOUT_VALUES = Set.of("single", "multi");
    private static final Set<String> DENSITY_VALUES = Set.of("comfortable", "compact");
    private static final Set<String> MEDIA_CORNERS_VALUES = Set.of("rounded", "square");
    private static final Set<String> FONT_VALUES = Set.of("system", "serif", "mono", "dyslexic");
    private static final Set<String> TEXT_SIZE_VALUES = Set.of("sm", "md", "lg", "xl");
    private static final Set<String> BOOLEAN_VALUES = Set.of("true", "false");

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
     * server default merged in for any unset known preference that HAS one (so the
     * toggle state is always complete for those). {@code domain} null = SUPERADMIN
     * cross-domain bypass.
     */
    public Mono<Map<String, String>> get(String owner, String domain) {
        requireOwner(owner);
        return repo.findAll(owner, domain).map(this::resolveOver);
    }

    /**
     * Merge the caller's DURABLE rows over the server defaults and canonicalise the
     * result: the user's explicit choices win, and the resolved view ALWAYS speaks the
     * user-facing contract vocabulary — a legacy engine token ({@code glaze}|…) still
     * sitting in a durable row is translated to {@code off|low|medium|high} on the way
     * out (see {@link #canonicalPoisonToken}).
     */
    private Map<String, String> resolveOver(Map<String, String> stored) {
        Map<String, String> out = new LinkedHashMap<>(defaults());
        out.putAll(stored);
        out.computeIfPresent(MEDIA_POISON_DEFAULT, (k, v) -> canonicalPoisonToken(v));
        return out;
    }

    /** Back-compat overload — operates on the platform {@code default} domain. */
    public Mono<Map<String, String>> put(String owner, String key, String value) {
        return put(owner, key, value, DomainRegistry.DEFAULT_DOMAIN);
    }

    /**
     * Upsert ONE durable preference for the owner in their domain, then return the
     * resolved view. The key is validated against the known-preference vocabulary and
     * the value against that preference's allowed values (the AI-poison default must
     * be a user-facing {@link MediaPoisonMode} token {@code off|low|medium|high}; an
     * appearance key must be one of its TS union values) so a client can never persist
     * a key/value the UI can't honour. {@code domain} null = SUPERADMIN cross-domain
     * bypass.
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

    /** The server-default view (no user rows) — every known preference THAT HAS a
     *  server-known default, at that default. The AI-poison default MIRRORS the
     *  server media poisoning policy ({@code MediaPoisoningProperties.defaultMode},
     *  an ENGINE token like {@code glaze}) translated to the user-facing
     *  {@link MediaPoisonMode} contract token ({@code medium}). Appearance keys have
     *  no server default here (see class doc) so they are absent until the user
     *  explicitly sets them. */
    Map<String, String> defaults() {
        Map<String, String> d = new LinkedHashMap<>();
        d.put(MEDIA_POISON_DEFAULT, canonicalPoisonToken(mediaProps.getDefaultMode()));
        return d;
    }

    /**
     * Canonicalise any {@code media.poison.default} representation to the USER-FACING
     * contract token: an already-canonical {@code off|low|medium|high} passes through;
     * a legacy/server ENGINE token ({@code glaze|nightshade|light|none}) is translated;
     * anything else (unreachable through the validated write path — a hand-edited row
     * or a misconfigured server default) falls back to {@code medium}, mirroring the
     * production {@code glaze} policy default, so the view never leaks an
     * out-of-vocabulary value.
     */
    static String canonicalPoisonToken(String raw) {
        String token = raw == null ? "" : raw.trim().toLowerCase();
        MediaPoisonMode canonical = MediaPoisonMode.fromWire(token);
        if (canonical != null) {
            return canonical.value();
        }
        MediaPoisonMode fromEngine = MediaPoisonMode.fromEngineToken(token);
        if (fromEngine != null) {
            return fromEngine.value();
        }
        return MediaPoisonMode.MEDIUM.value();
    }

    /** True iff {@code key} is a preference this BFF recognises (fail-closed on
     *  anything else so the durable store can't be turned into arbitrary storage). */
    static boolean isKnownKey(String key) {
        return MEDIA_POISON_DEFAULT.equals(key) || APPEARANCE_KEYS.contains(key);
    }

    /** Validate + canonicalise a value for the given known key. The AI-poison default
     *  must be one of the USER-FACING {@link MediaPoisonMode} tokens
     *  ({@code off|low|medium|high} — STRICT: the engine tokens are not accepted on
     *  the wire); an appearance key must be one of its TS union values (booleans as
     *  {@code "true"|"false"}); reject anything else as a clean 400 so a bad value
     *  never reaches the durable row. */
    private static String normalizeValue(String key, String rawValue) {
        String v = rawValue == null ? "" : rawValue.trim();
        if (MEDIA_POISON_DEFAULT.equals(key)) {
            MediaPoisonMode mode = MediaPoisonMode.fromWire(v.toLowerCase());
            if (mode == null) {
                throw ApiException.badRequest(
                        "media.poison.default must be " + MediaPoisonMode.VOCABULARY);
            }
            return mode.value();
        }
        if (APPEARANCE_KEYS.contains(key)) {
            return normalizeAppearanceValue(key, v);
        }
        return v;
    }

    private static String normalizeAppearanceValue(String key, String v) {
        String lower = v.toLowerCase();
        Set<String> allowed = allowedValuesFor(key);
        boolean bool = key.equals(APPEARANCE_HIGH_CONTRAST) || key.equals(APPEARANCE_REDUCED_MOTION);
        String candidate = bool ? lower : v;
        if (!allowed.contains(candidate)) {
            throw ApiException.badRequest(key + " must be one of: " + String.join("|", sorted(allowed)));
        }
        return candidate;
    }

    private static Set<String> allowedValuesFor(String key) {
        if (key.equals(APPEARANCE_THEME)) return THEME_VALUES;
        if (key.equals(APPEARANCE_ACCENT)) return ACCENT_VALUES;
        if (key.equals(APPEARANCE_APPEARANCE)) return APPEARANCE_MODE_VALUES;
        if (key.equals(APPEARANCE_LAYOUT)) return LAYOUT_VALUES;
        if (key.equals(APPEARANCE_DENSITY)) return DENSITY_VALUES;
        if (key.equals(APPEARANCE_MEDIA_CORNERS)) return MEDIA_CORNERS_VALUES;
        if (key.equals(APPEARANCE_FONT)) return FONT_VALUES;
        if (key.equals(APPEARANCE_TEXT_SIZE)) return TEXT_SIZE_VALUES;
        return BOOLEAN_VALUES; // highContrast / reducedMotion
    }

    private static java.util.List<String> sorted(Set<String> values) {
        var list = new java.util.ArrayList<>(values);
        java.util.Collections.sort(list);
        return list;
    }

    private static void requireOwner(String owner) {
        if (owner == null || owner.isBlank()) {
            throw ApiException.unauthorized("missing authenticated subject");
        }
    }
}
