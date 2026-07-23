package systems.hugmesh.userbff.preference;

import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import systems.hugmesh.commons.security.DomainRegistry;
import systems.hugmesh.commons.web.ApiException;

/**
 * Owner-enforced home/getting-started-guide dismissal preference. The role home
 * views read {@link #isDismissed} to show the welcome guide ONLY on first visit;
 * the user dismisses it via {@link #dismiss} (or re-shows it via {@link #reset}).
 *
 * <p>Stored as one {@code user_preference} row per guide key
 * ({@code home-guide-dismissed:<guide>}, value {@code "true"}). EVERY method takes
 * the owner (JWT subject) and operates only on that owner's preferences — a user
 * can never read/write another user's guide state.
 */
@Service
public class HomeGuideService {

    /** Preference-key prefix for the per-guide dismissed flag. */
    static final String KEY_PREFIX = "home-guide-dismissed:";
    /** The default guide key when the caller does not name one. */
    public static final String DEFAULT_GUIDE = "home";
    private static final String TRUE = "true";

    private final UserPreferenceRepository repo;

    public HomeGuideService(UserPreferenceRepository repo) {
        this.repo = repo;
    }

    /** True if the owner has dismissed the named guide (within their domain;
     *  {@code domain} null = SUPERADMIN cross-domain bypass). */
    public Mono<Boolean> isDismissed(String owner, String guide, String domain) {
        requireOwner(owner);
        return repo.find(owner, keyFor(guide), domain).map(TRUE::equals).defaultIfEmpty(false);
    }

    /** Back-compat overload — scopes to the platform {@code default} domain. */
    public Mono<Boolean> isDismissed(String owner, String guide) {
        return isDismissed(owner, guide, DomainRegistry.DEFAULT_DOMAIN);
    }

    /** Back-compat overload — scopes to the platform {@code default} domain. */
    public Mono<Void> dismiss(String owner, String guide) {
        return dismiss(owner, guide, DomainRegistry.DEFAULT_DOMAIN);
    }

    /** Back-compat overload — scopes to the platform {@code default} domain. */
    public Mono<Void> reset(String owner, String guide) {
        return reset(owner, guide, DomainRegistry.DEFAULT_DOMAIN);
    }

    /** Mark the named guide dismissed for the owner in their domain (idempotent). */
    public Mono<Void> dismiss(String owner, String guide, String domain) {
        requireOwner(owner);
        return repo.set(owner, keyFor(guide), TRUE, domain);
    }

    /** Un-dismiss (re-show) the named guide for the owner in their domain. */
    public Mono<Void> reset(String owner, String guide, String domain) {
        requireOwner(owner);
        return repo.delete(owner, keyFor(guide), domain);
    }

    static String keyFor(String guide) {
        String g = (guide == null || guide.isBlank()) ? DEFAULT_GUIDE : guide.trim();
        return KEY_PREFIX + g;
    }

    private static void requireOwner(String owner) {
        if (owner == null || owner.isBlank()) {
            throw ApiException.unauthorized("missing authenticated subject");
        }
    }
}
