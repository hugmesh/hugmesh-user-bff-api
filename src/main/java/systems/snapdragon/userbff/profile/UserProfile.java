package systems.snapdragon.userbff.profile;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * The caller's OWN profile (table {@code user_profile}). {@code userId} is the
 * Casdoor JWT subject and the row's PRIMARY KEY — there is exactly one profile per
 * user and a user only ever reads/writes their own (owner-enforcement lives in
 * {@code ProfileService}). {@code visibility} is {@code public|internal} (default
 * {@code internal}).
 *
 * <p>This record is the WIRE shape AND the persisted shape. {@code userId} is
 * never accepted from the request body — the controller always overwrites it with
 * the JWT subject — so a caller cannot spoof another user's id.
 */
public record UserProfile(
        @JsonProperty("userId") String userId,
        String gender,
        String pronouns,
        String timezone,
        String displayName,
        String visibility,
        boolean vanitySubdomainEnabled) {

    /** Default visibility floor — private to the platform unless the user opts in. */
    public static final String DEFAULT_VISIBILITY = "internal";

    /** An empty (not-yet-created) profile for the given owner. */
    public static UserProfile empty(String userId) {
        return new UserProfile(userId, null, null, null, null, DEFAULT_VISIBILITY, false);
    }

    /** A copy with the owner forced to {@code userId} and visibility normalized. */
    public UserProfile withOwner(String userId) {
        String vis = ("public".equals(visibility)) ? "public" : DEFAULT_VISIBILITY;
        return new UserProfile(userId, gender, pronouns, timezone, displayName, vis, vanitySubdomainEnabled);
    }
}
