package systems.snapdragon.userbff.profile;

import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import systems.snapdragon.userbff.web.ApiException;

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

    /** The owner's own profile; an empty default if they have none yet. */
    public Mono<UserProfile> get(String owner) {
        requireOwner(owner);
        return repo.find(owner).defaultIfEmpty(UserProfile.empty(owner));
    }

    /**
     * Create/update the OWNER's profile. The owner is forced onto the row so the
     * request body's {@code userId} can never redirect the write to another user.
     */
    public Mono<UserProfile> save(String owner, UserProfile body) {
        requireOwner(owner);
        UserProfile owned = (body == null ? UserProfile.empty(owner) : body).withOwner(owner);
        return repo.save(owned);
    }

    public Mono<Void> delete(String owner) {
        requireOwner(owner);
        return repo.delete(owner);
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
