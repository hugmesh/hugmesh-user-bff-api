package net.hugmesh.userbff.notification;

import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.commons.web.ApiException;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Owner-enforced per-category notification preferences, MIRRORING
 * {@link net.hugmesh.userbff.prefstore.UserPreferencesService} EXACTLY. EVERY
 * method takes the owner (the JWT subject) and operates ONLY on that owner's
 * preferences in that owner's domain — a user can never read/write another user's (or
 * brand's) preferences.
 *
 * <p>Resolution is DEFAULTS-MERGED: {@link #get} returns the default for any category
 * the user has not explicitly set, so the UI always renders a complete, honest toggle
 * state. Every category defaults to ENABLED (opt-out, not opt-in).
 *
 * <p>The {@code account-restriction} category is FORCED-ON / un-silenceable: {@link #put}
 * COERCES {@code enabled=false} to {@code true} on it (the durable row + the resolved
 * view always show it enabled), and {@link #get} forces it enabled even if a stale row
 * somehow said otherwise. The 012-3 DB CHECK is the backstop. A user can NEVER silence
 * being told their account was restricted.
 */
@Service
public class NotificationPreferenceService {

    private final NotificationPreferenceRepository repo;

    public NotificationPreferenceService(NotificationPreferenceRepository repo) {
        this.repo = repo;
    }

    /** Back-compat overload — scopes to the platform {@code default} domain. */
    public Mono<Map<String, Boolean>> get(String owner) {
        return get(owner, DomainRegistry.DEFAULT_DOMAIN);
    }

    /**
     * The owner's resolved per-category preferences in their domain: every category at
     * its default (ENABLED), with the user's explicit stored choices merged in. The
     * FORCED-ON {@code account-restriction} is ALWAYS enabled in the resolved view.
     * {@code domain} null = SUPERADMIN cross-domain bypass.
     */
    public Mono<Map<String, Boolean>> get(String owner, String domain) {
        requireOwner(owner);
        // Load all stored rows and merge them on top of the all-enabled defaults.
        return repo.findAll(owner, domain).map(stored -> mergeWithDefaults(stored));
    }

    /** Merge stored preference rows onto the all-enabled default map; force account-restriction on. */
    private Map<String, Boolean> mergeWithDefaults(Map<String, Boolean> stored) {
        Map<String, Boolean> out = new LinkedHashMap<>(defaults());
        for (Map.Entry<String, Boolean> e : stored.entrySet()) {
            // ignore any stored category the BFF no longer recognises (fail-closed
            // on vocabulary drift), and never let a stored value override a default
            // category we don't expose.
            if (NotificationCategory.isValid(e.getKey())) {
                out.put(e.getKey(), e.getValue());
            }
        }
        // FORCED-ON: account-restriction is always enabled regardless of any row.
        out.put(NotificationCategory.ACCOUNT_RESTRICTION, Boolean.TRUE);
        return out;
    }

    /** Back-compat overload — operates on the platform {@code default} domain. */
    public Mono<Map<String, Boolean>> put(String owner, String category, boolean enabled) {
        return put(owner, category, enabled, DomainRegistry.DEFAULT_DOMAIN);
    }

    /**
     * Upsert ONE category preference for the owner in their domain, then return the
     * resolved view. The category is validated against the known vocabulary (fail-closed
     * 400 on anything else). The FORCED-ON {@code account-restriction} is COERCED to
     * enabled — a {@code put(account-restriction, false)} persists enabled=true and the
     * resolved view shows it enabled (never silenced). {@code domain} null = SUPERADMIN
     * cross-domain bypass.
     */
    public Mono<Map<String, Boolean>> put(String owner, String category, boolean enabled, String domain) {
        requireOwner(owner);
        String cat = category == null ? "" : category.trim();
        if (!NotificationCategory.isValid(cat)) {
            return Mono.error(ApiException.badRequest("unknown notification category"));
        }
        // FORCED-ON: account-restriction can never be silenced — coerce to enabled.
        boolean effectiveEnabled = NotificationCategory.isForcedOn(cat) || enabled;
        return repo.upsert(owner, cat, effectiveEnabled, domain).then(get(owner, domain));
    }

    /** The default view (no user rows): every known category ENABLED (opt-out, not
     *  opt-in). account-restriction is enabled here too (and forced enabled in get). */
    Map<String, Boolean> defaults() {
        Map<String, Boolean> d = new LinkedHashMap<>();
        for (String c : NotificationCategory.ALL) {
            d.put(c, Boolean.TRUE);
        }
        return d;
    }

    private static void requireOwner(String owner) {
        if (owner == null || owner.isBlank()) {
            throw ApiException.unauthorized("missing authenticated subject");
        }
    }
}
