package systems.snapdragon.userbff.profile;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import systems.snapdragon.userbff.web.SafeDisplayName;
import systems.snapdragon.userbff.web.SafeScreenReaderName;
import systems.snapdragon.userbff.web.ScreenReaderNames;
import systems.snapdragon.userbff.web.ValidationPatterns;

/**
 * The caller's OWN profile (table {@code user_profile}). {@code userId} is the
 * Casdoor JWT subject and the row's PRIMARY KEY — there is exactly one profile per
 * user and a user only ever reads/writes their own (owner-enforcement lives in
 * {@code ProfileService}). {@code visibility} is {@code public|internal} (default
 * {@code internal}).
 *
 * <p>This record is the WIRE shape AND the persisted shape. {@code userId} is
 * never accepted from the request body — the controller always overwrites it with
 * the JWT subject — so a caller cannot spoof another user's id. The same is true of
 * {@code vanityUsername} (the normalized Casdoor username that backs the vanity
 * subdomain): it is SERVER-DERIVED from the JWT's {@code preferred_username} claim
 * and set ONLY when vanity is enabled, never read from the request body.
 *
 * @param vanityUsername normalized (lower-cased) Casdoor username, set ONLY when
 *        {@code vanitySubdomainEnabled} is true; NULL otherwise. This is the DNS
 *        label served at {@code <vanityUsername>.snapdragon.systems}. NOT client-
 *        supplied — the controller overwrites it from the JWT (see ProfileService).
 * @param screenReaderName the a11y aria-label / spoken name a screen reader announces
 *        — ASCII-only ({@link SafeScreenReaderName}). When the {@code displayName} is
 *        pure ASCII this DEFAULTS to it; when the display name is non-ASCII a
 *        screen-reader name must be supplied (the save flow prompts with a 422
 *        otherwise). NULL when not yet set + the display name is ASCII (the read side
 *        defaults from the display name). The aria-label UI consumption is a later
 *        UI-wave task — this carries the field + validation only.
 */
public record UserProfile(
        @JsonProperty("userId") String userId,
        @Size(max = 64, message = "gender must be at most 64 chars") String gender,
        @Size(max = 64, message = "pronouns must be at most 64 chars") String pronouns,
        @Size(max = 64, message = "timezone must be at most 64 chars") String timezone,
        @Size(max = 255, message = "displayName must be at most 255 chars")
        @SafeDisplayName String displayName,
        // Null is allowed (the service defaults/normalizes it); a NON-null value
        // must be the public|internal vocabulary (mirrors the 005
        // ck_user_profile_visibility CHECK), so a clearly-wrong value is a 400
        // instead of being silently coerced.
        @Pattern(regexp = ValidationPatterns.VISIBILITY, message = "visibility must be public|internal")
        String visibility,
        boolean vanitySubdomainEnabled,
        @JsonProperty(access = JsonProperty.Access.READ_ONLY) String vanityUsername,
        @Size(max = 255, message = "screenReaderName must be at most 255 chars")
        @SafeScreenReaderName String screenReaderName) {

    /** Default visibility floor — private to the platform unless the user opts in. */
    public static final String DEFAULT_VISIBILITY = "internal";

    /** Back-compat constructor (no explicit vanityUsername / screenReaderName → null).
     *  The vanity username is always server-derived; the screen-reader name is
     *  defaulted/prompted by the service. Callers that don't supply them get null,
     *  which the DB CHECK's {@code IS NULL} branch accepts. */
    public UserProfile(String userId, String gender, String pronouns, String timezone,
                       String displayName, String visibility, boolean vanitySubdomainEnabled) {
        this(userId, gender, pronouns, timezone, displayName, visibility,
                vanitySubdomainEnabled, null, null);
    }

    /** Back-compat constructor (explicit vanityUsername, no screenReaderName → null). */
    public UserProfile(String userId, String gender, String pronouns, String timezone,
                       String displayName, String visibility, boolean vanitySubdomainEnabled,
                       String vanityUsername) {
        this(userId, gender, pronouns, timezone, displayName, visibility,
                vanitySubdomainEnabled, vanityUsername, null);
    }

    /** An empty (not-yet-created) profile for the given owner. */
    public static UserProfile empty(String userId) {
        return new UserProfile(userId, null, null, null, null, DEFAULT_VISIBILITY, false, null, null);
    }

    /** A copy with the owner forced to {@code userId} and visibility normalized.
     *  {@code vanityUsername} is NOT set here — {@link #withVanityUsername(String)}
     *  is applied by the service once the JWT username is known + validated.
     *  {@code screenReaderName} is preserved (defaulting is applied separately by the
     *  service via {@link #withDefaultedScreenReaderName()}). */
    public UserProfile withOwner(String userId) {
        String vis = ("public".equals(visibility)) ? "public" : DEFAULT_VISIBILITY;
        return new UserProfile(userId, gender, pronouns, timezone, displayName, vis,
                vanitySubdomainEnabled, vanityUsername, screenReaderName);
    }

    /**
     * A copy whose {@code vanityUsername} mirrors the given (already lower-cased)
     * Casdoor username when vanity is ENABLED, and is NULL otherwise. The DB CHECK
     * (changeset 004) + the service-layer validation reject a reserved username.
     */
    public UserProfile withVanityUsername(String username) {
        String vu = vanitySubdomainEnabled && username != null && !username.isBlank()
                ? username.trim().toLowerCase()
                : null;
        return new UserProfile(userId, gender, pronouns, timezone, displayName, visibility,
                vanitySubdomainEnabled, vu, screenReaderName);
    }

    /**
     * A copy with an explicit {@code screenReaderName}.
     */
    public UserProfile withScreenReaderName(String screenReaderName) {
        return new UserProfile(userId, gender, pronouns, timezone, displayName, visibility,
                vanitySubdomainEnabled, vanityUsername, screenReaderName);
    }

    /**
     * A copy whose {@code screenReaderName} is DEFAULTED from the display name when it
     * is absent + the display name is pure ASCII: a user who never typed a screen-
     * reader name but has an ASCII display name gets it as their spoken name for free.
     * When a screen-reader name is already present it is kept verbatim; when the
     * display name is non-ASCII and no screen-reader name is set, the field stays NULL
     * here (the save flow prompts via {@link ScreenReaderNames#requiresScreenReaderName}).
     */
    public UserProfile withDefaultedScreenReaderName() {
        if (screenReaderName != null && !screenReaderName.isBlank()) {
            return this;
        }
        String defaulted = ScreenReaderNames.defaultFor(displayName);
        return defaulted == null ? this : withScreenReaderName(defaulted);
    }
}
