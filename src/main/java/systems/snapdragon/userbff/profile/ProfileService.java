package systems.snapdragon.userbff.profile;

import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import systems.snapdragon.commons.security.DomainRegistry;
import systems.snapdragon.commons.web.ApiException;
import systems.snapdragon.userbff.web.ScreenReaderNames;

/**
 * Owner-enforced profile operations. EVERY method takes the caller's id
 * ({@code owner} = the JWT subject, passed by the controller from the validated
 * token) and operates ONLY on that owner's row:
 *
 * <ul>
 *   <li>{@link #get(String)} reads the owner's own profile (a missing one is
 *       returned as an empty default — never another user's);</li>
 *   <li>{@link #save(String, UserProfile)} forces the persisted owner to the
 *       caller — the {@code userId} in the request body is IGNORED, so a user
 *       cannot write into another user's row by spoofing the body;</li>
 *   <li>{@link #delete(String)} removes only the owner's row.</li>
 * </ul>
 *
 * <p>Password + email changes are NOT stored here — they go to the Casdoor IdP via
 * {@link CasdoorUserClient}, again keyed to the caller's own username.
 */
@Service
public class ProfileService {

    private final UserProfileRepository repo;
    private final CasdoorUserClient casdoor;

    public ProfileService(UserProfileRepository repo, CasdoorUserClient casdoor) {
        this.repo = repo;
        this.casdoor = casdoor;
    }

    /** The owner's own profile; an empty default if they have none yet. Back-compat
     *  overload — scopes to the platform {@code default} domain (single-tenant). */
    public Mono<UserProfile> get(String owner) {
        return get(owner, DomainRegistry.DEFAULT_DOMAIN);
    }

    /** The owner's own profile within their DOMAIN; an empty default if they have
     *  none yet. {@code domain} is the caller's validated-issuer brand (or
     *  {@code null} for the SUPERADMIN cross-domain bypass). Owner-enforcement is
     *  UNWEAKENED — domain is an additional predicate. */
    public Mono<UserProfile> get(String owner, String domain) {
        requireOwner(owner);
        return repo.find(owner, domain).defaultIfEmpty(UserProfile.empty(owner));
    }

    /**
     * Create/update the OWNER's profile. The owner is forced onto the row so the
     * request body's {@code userId} can never redirect the write to another user.
     *
     * <p>Back-compat overload — no username is threaded through, so the vanity
     * RESERVED-USERNAME guard cannot fire (there is no DNS label to reserve). It does
     * NOT skip the {@code displayName} charset/confusable guard, which runs on EVERY
     * path so an impersonation displayName ({@code admin}, a zero-width / Cyrillic
     * look-alike) cannot be smuggled in via this overload. Prefer
     * {@link #save(String, String, UserProfile)} which ALSO applies the reserved
     * username guard. (See {@code save(owner, username, body)}.)
     */
    public Mono<UserProfile> save(String owner, UserProfile body) {
        return save(owner, null, body, DomainRegistry.DEFAULT_DOMAIN);
    }

    /** Back-compat overload (no explicit domain) — scopes to the platform
     *  {@code default} domain (single-tenant). */
    public Mono<UserProfile> save(String owner, String username, UserProfile body) {
        return save(owner, username, body, DomainRegistry.DEFAULT_DOMAIN);
    }

    /**
     * Create/update the OWNER's profile, threading the caller's USERNAME (the
     * Casdoor {@code preferred_username} claim, derived by the controller from the
     * JWT — see {@link ProfileController}). {@code owner} is the JWT SUBJECT (the
     * row key); {@code username} is the vanity DNS label.
     *
     * <p>RESERVED-USERNAME GUARD: enabling the vanity subdomain (or making the
     * profile public) is REJECTED with 400 when the caller's username is a reserved
     * label ({@link ReservedNames}) OR a CONFUSABLE of one ({@code 4dmin~admin},
     * {@code akk0ma~akkoma} — {@link UsernameSkeleton#isReservedConfusable}), because
     * {@code <username>.snapdragon.systems} would collide with (or impersonate) a
     * dedicated app route. When allowed + vanity-enabled, the normalized username is
     * mirrored into {@code vanity_username} (DB-CHECK-backed).
     *
     * <p>DISPLAYNAME GUARD: {@code displayName} is free text but is the human-visible
     * impersonation surface, so it is charset/confusable-checked on EVERY save (both
     * overloads converge here) — a zero-width / bidi / format code point or a
     * reserved-confusable display name ({@code admin}, Cyrillic {@code аdmin}) is
     * rejected with 400. See {@link #guardDisplayName(String)}.
     *
     * <p>SCREEN-READER NAME (a11y): the spoken/aria-label name is DEFAULTED from the
     * display name when the display name is pure ASCII (no prompt). When the display
     * name is NON-ASCII and no usable ASCII screen-reader name was supplied, the save
     * is REJECTED with 422 so the registration/profile-save flow prompts for one (see
     * {@link ScreenReaderNames}). Its ASCII charset is also re-checked here (service
     * leg) alongside the {@code @SafeScreenReaderName} API-leg constraint.
     */
    public Mono<UserProfile> save(String owner, String username, UserProfile body, String domain) {
        requireOwner(owner);
        UserProfile owned = (body == null ? UserProfile.empty(owner) : body)
                .withOwner(owner)
                .withVanityUsername(username)
                .withDefaultedScreenReaderName();

        ApiException displayNameViolation = guardDisplayName(owned.displayName());
        if (displayNameViolation != null) {
            return Mono.error(displayNameViolation);
        }

        ApiException screenReaderViolation = guardScreenReaderName(
                owned.displayName(), owned.screenReaderName());
        if (screenReaderViolation != null) {
            return Mono.error(screenReaderViolation);
        }

        boolean wantsVanity = owned.vanitySubdomainEnabled();
        boolean wantsPublic = "public".equals(owned.visibility());
        if (wantsVanity || wantsPublic) {
            if (ReservedNames.isReserved(username)) {
                return Mono.error(ApiException.badRequest(
                        "username '" + username + "' is a reserved platform name and cannot be "
                                + "used as a vanity subdomain or public profile (it would collide "
                                + "with a dedicated app route)"));
            }
            // Reserved-CONFUSABLE: a look-alike of a reserved label (4dmin, akk0ma,
            // ad-min, Cyrillic admin) is rejected too — fail CLOSED, never weakening
            // the exact reserved rule above, only widening it.
            if (UsernameSkeleton.isReservedConfusable(username)) {
                return Mono.error(ApiException.badRequest(
                        "username '" + username + "' is confusable with a reserved platform name "
                                + "and cannot be used as a vanity subdomain or public profile"));
            }
        }
        return repo.save(owned, domain);
    }

    /**
     * The displayName charset + confusable guard (GAP 2 of the impersonation design).
     * {@code displayName} is {@code @Size(max=255)} free text in {@link UserProfile}
     * with no other constraint, yet it is the actual human-visible impersonation
     * vector, so it is guarded on every save:
     * <ul>
     *   <li>REJECT any zero-width / bidi-control / format (Cf) / default-ignorable
     *       code point — these have no place in a visible name and are a classic
     *       homograph-smuggling vector;</li>
     *   <li>REJECT a value that is CONFUSABLE with a reserved platform label (so a
     *       user cannot set their display name to {@code admin}, {@code 4dmin}, or a
     *       Cyrillic look-alike to impersonate the platform / staff).</li>
     * </ul>
     * User-vs-user displayName collisions are NOT hard-rejected here (the design
     * leaves those to a soft flag-for-review); this guard is the hard charset +
     * reserved-impersonation floor.
     *
     * @return a 400 {@link ApiException} to fail with, or {@code null} when the
     *         displayName is acceptable (or absent).
     */
    static ApiException guardDisplayName(String displayName) {
        if (displayName == null || displayName.isBlank()) {
            return null;
        }
        if (UsernameSkeleton.hasForbiddenInvisible(displayName)) {
            return ApiException.badRequest(
                    "displayName must not contain zero-width, bidirectional, or format "
                            + "control characters");
        }
        if (UsernameSkeleton.isReservedConfusable(displayName)) {
            return ApiException.badRequest(
                    "displayName '" + displayName + "' is confusable with a reserved platform "
                            + "name and cannot be used (it would impersonate a platform service "
                            + "or role)");
        }
        return null;
    }

    /**
     * The screen-reader-name guard (the a11y default/prompt floor). After the service
     * defaults the screen-reader name from an ASCII display name
     * ({@link UserProfile#withDefaultedScreenReaderName()}), this enforces:
     * <ul>
     *   <li>a PRESENT screen-reader name must be ASCII-only + free of invisibles (400)
     *       — defence-in-depth alongside the {@code @SafeScreenReaderName} API leg;</li>
     *   <li>a NON-ASCII display name with NO usable screen-reader name is a 422 PROMPT
     *       (the registration/profile-save flow must collect an ASCII spoken name).</li>
     * </ul>
     *
     * @return a 400/422 {@link ApiException} to fail with, or {@code null} when the
     *         screen-reader name is acceptable (defaulted, supplied-and-valid, or not
     *         required).
     */
    static ApiException guardScreenReaderName(String displayName, String screenReaderName) {
        if (screenReaderName != null && !screenReaderName.isBlank()
                && !ScreenReaderNames.isSafeScreenReaderName(screenReaderName)) {
            return ApiException.badRequest(
                    "screenReaderName must be ASCII-only with no special, invisible, or "
                            + "control characters (it is the name a screen reader announces)");
        }
        if (ScreenReaderNames.requiresScreenReaderName(displayName, screenReaderName)) {
            return ApiException.unprocessable(
                    "displayName '" + displayName + "' is not plain ASCII, so a screenReaderName "
                            + "(an ASCII spoken/aria-label name) is required");
        }
        return null;
    }

    /** Back-compat overload — scopes to the platform {@code default} domain. */
    public Mono<Void> delete(String owner) {
        return delete(owner, DomainRegistry.DEFAULT_DOMAIN);
    }

    /** Delete the owner's profile within their DOMAIN ({@code null} = SUPERADMIN
     *  cross-domain bypass). */
    public Mono<Void> delete(String owner, String domain) {
        requireOwner(owner);
        return repo.delete(owner, domain);
    }

    /**
     * Self-service password change → Casdoor IdP (the caller's own credential).
     * {@code owner} is the JWT subject, mapped to the Casdoor username — a user can
     * only ever change their own password.
     */
    public Mono<Void> changePassword(String owner, String oldPassword, String newPassword) {
        requireOwner(owner);
        if (newPassword == null || newPassword.isBlank()) {
            return Mono.error(ApiException.badRequest("newPassword required"));
        }
        return casdoor.changePassword(usernameOf(owner), oldPassword, newPassword);
    }

    /** Self-service email change → Casdoor IdP (the caller's own identity). */
    public Mono<Void> changeEmail(String owner, String newEmail) {
        requireOwner(owner);
        if (newEmail == null || newEmail.isBlank()) {
            return Mono.error(ApiException.badRequest("email required"));
        }
        return casdoor.changeEmail(usernameOf(owner), newEmail);
    }

    /** Whether the live Casdoor account write is wired (vs. the documented stub). */
    public boolean casdoorEnabled() { return casdoor.enabled(); }

    /** Casdoor username for the JWT subject. The subject already IS the Casdoor
     *  user name in this platform (the gateway mints the JWT from Casdoor), so it
     *  maps through unchanged; centralised here so the mapping has one home. */
    private static String usernameOf(String owner) { return owner; }

    private static void requireOwner(String owner) {
        if (owner == null || owner.isBlank()) {
            throw ApiException.unauthorized("missing authenticated subject");
        }
    }
}
