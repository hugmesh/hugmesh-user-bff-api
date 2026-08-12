package net.hugmesh.userbff.media;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.List;

/**
 * Bound configuration for the BFF media-proxy / AI-cloak ({@code app.media.poisoning.*}).
 * The server owns the cloak policy; these knobs let an operator tune strength, the
 * worker URL, the latency budget, the pinned thumbnail sizes, and — critically — the
 * LEAN FALLBACK behaviour when the optional heavy-tier worker is absent.
 */
@ConfigurationProperties(prefix = "app.media.poisoning")
public class MediaPoisoningProperties {

    /**
     * What to do when the poisoner worker is ABSENT (heavy tier not present — its
     * {@code /health} reports {@code backend=none}) and the user did NOT opt out:
     * <ul>
     *   <li>{@code skip} (default) — forward the bytes through UNCLOAKED and record
     *       {@code status=skipped} + a documented signal so the UI warns "not cloaked"
     *       (honest; never silently implies protection);</li>
     *   <li>{@code light} — attempt the reduced-strength CPU path IF the worker offers
     *       a CPU backend (still subject to the survival gate; otherwise behaves as
     *       {@code skip});</li>
     *   <li>{@code queue} — reserved for the placeholder-then-replace path (documented;
     *       behaves as {@code skip} here until the worker queue lands).</li>
     * </ul>
     */
    public enum FallbackMode { SKIP, LIGHT, QUEUE;
        public static FallbackMode parse(String s) {
            if (s == null) return SKIP;
            return switch (s.trim().toLowerCase()) {
                case "light" -> LIGHT;
                case "queue" -> QUEUE;
                default -> SKIP;
            };
        }
    }

    /** Master gate for the whole media-proxy. When false the controller is still
     *  mounted but every upload is forwarded-through with {@code status=none} (the
     *  feature ships dark first, flipped on only after the survival gate is verified). */
    private boolean enabled = false;

    /** The default cloak mode for an opted-in image (the UI shows this as default-ON). */
    private String defaultMode = "glaze";

    /** Behaviour when the worker is absent — string-bound, parsed to {@link FallbackMode}. */
    private String fallbackMode = "skip";

    /** The served thumbnail sizes to ALSO poison so no clean derivative exists
     *  (akkoma "small"; Matrix 240x240 — enumerated + pinned). */
    private List<String> thumbnailSizes = new ArrayList<>(List.of("small", "240x240"));

    /** Hard per-job latency budget (ms) for the worker poison/survival calls. */
    private long timeoutMs = 120_000;

    /** Worker /health probe timeout (ms) — short so capability queries never hang. */
    private long healthTimeoutMs = 2_000;

    /** Max accepted upload size (bytes) the controller enforces before holding bytes. */
    private long maxUploadBytes = 20L * 1024 * 1024;

    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }
    public String getDefaultMode() { return defaultMode; }
    public void setDefaultMode(String defaultMode) { this.defaultMode = defaultMode; }
    public String getFallbackMode() { return fallbackMode; }
    public void setFallbackMode(String fallbackMode) { this.fallbackMode = fallbackMode; }
    public List<String> getThumbnailSizes() { return thumbnailSizes == null ? List.of() : List.copyOf(thumbnailSizes); }
    /**
     * Copy on the way IN. {@link #getThumbnailSizes()} already copies on the way out, but
     * that left the field aliased to the binder-supplied list; this is a singleton
     * {@code @ConfigurationProperties} bean, so a retained reference could mutate the
     * pinned size set for the whole application at runtime. Null is preserved — the getter
     * maps it to an empty list.
     */
    public void setThumbnailSizes(List<String> thumbnailSizes) {
        this.thumbnailSizes = thumbnailSizes == null ? null : List.copyOf(thumbnailSizes);
    }
    public long getTimeoutMs() { return timeoutMs; }
    public void setTimeoutMs(long timeoutMs) { this.timeoutMs = timeoutMs; }
    public long getHealthTimeoutMs() { return healthTimeoutMs; }
    public void setHealthTimeoutMs(long healthTimeoutMs) { this.healthTimeoutMs = healthTimeoutMs; }
    public long getMaxUploadBytes() { return maxUploadBytes; }
    public void setMaxUploadBytes(long maxUploadBytes) { this.maxUploadBytes = maxUploadBytes; }

    public FallbackMode fallback() { return FallbackMode.parse(fallbackMode); }
}
