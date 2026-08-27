package net.hugmesh.userbff.profile;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import net.hugmesh.authcore.reserved.ReservedNames;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.commons.web.ApiException;
import net.hugmesh.userbff.federation.FederationApiClient;
import net.hugmesh.userbff.web.ScreenReaderNames;

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
 *
 * <h2>Vanity PUBLISH sync (the federation-api "missing link")</h2>
 * <p>The username-threading overloads ({@link #save(String, String, UserProfile)} /
 * {@link #save(String, String, UserProfile, String)}) additionally SYNC the caller's
 * federation-api vanity fragment on every save, via {@link FederationApiClient}:
 * <ul>
 *   <li>{@code vanitySubdomainEnabled && visibility=='public'} → {@code PUT
 *       /api/federation/vanity/{username}} (self-publish, owner-scoped upstream).
 *       This is the user's ACTIVE, explicit intent, so a federation-api FAILURE
 *       (e.g. no bundle uploaded yet, or an upstream outage) FAILS THE WHOLE
 *       {@code save} call — never swallowed into a silently-degraded success, so
 *       the caller (and the UI) never sees {@code visibility=public} reported as
 *       saved while the federation registry never actually got the fragment.
 *       This leg runs BEFORE the local {@code repo.save}, so a refusal also leaves
 *       {@code user_profile} untouched — the error the caller is shown and the row
 *       they read back on the next page load always agree.</li>
 *   <li>otherwise → {@code DELETE /api/federation/vanity/{username}} (self-unpublish;
 *       idempotent no-op upstream when nothing was ever published). This call fires
 *       on EVERY non-public save — including profile edits that never touched
 *       vanity at all — so it is deliberately BEST-EFFORT: a federation-api failure
 *       here is logged and does NOT fail the save (an unrelated pronoun/timezone
 *       edit must not 500 because the vanity-unpublish leg, or federation-api
 *       itself, is unreachable). The local {@code user_profile} row — this
 *       platform's own source of truth for visibility — is already correctly
 *       private the moment the save completes; a lagging federation unpublish
 *       converges on the next successful sync. This leg therefore keeps the
 *       persist-THEN-sync order. See {@link #syncVanityUnpublish}.</li>
 * </ul>
 * The back-compat overload {@link #save(String, UserProfile)} threads NO username,
 * so it can never sync (there is no vanity target) — unchanged from its pre-existing
 * contract.
 */
@Service
public class ProfileService {

    private static final Logger log = LoggerFactory.getLogger(ProfileService.class);

    private final UserProfileRepository repo;
    private final CasdoorUserClient casdoor;
    private final FederationApiClient federation;

    public ProfileService(UserProfileRepository repo, CasdoorUserClient casdoor,
                          FederationApiClient federation) {
        this.repo = repo;
        this.casdoor = casdoor;
        this.federation = federation;
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
     * The owner's stored avatar pixels + the SNIFFED MIME recorded at save, or EMPTY
     * when they have no stored picture (pre-022 rows, and anyone who never uploaded).
     *
     * <p>Deliberately NOT part of {@link #get}: pixels must never ride the profile
     * JSON. The serve route consumes this and 404s on the empty case, which is the
     * same outcome those rows always had.
     */
    public Mono<UserProfileRepository.AvatarBody> findAvatarBody(String owner, String domain) {
        requireOwner(owner);
        return repo.findAvatarBody(owner, domain);
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
     * {@code <username>.hugmesh.net} would collide with (or impersonate) a
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
     *
     * <p>FEDERATION SYNC: the caller's federation-api vanity fragment is synced to
     * match (publish or unpublish — see the class Javadoc).
     *
     * <p><b>ORDER MATTERS — the PUBLISH leg runs BEFORE the local write.</b> The two
     * legs of a public+vanity save are a local row and a cross-service registration,
     * and there is no distributed transaction over them, so the ORDER decides what a
     * partial failure leaves behind. Publishing FIRST means a refused publish (403
     * owner mismatch, 404 no uploaded bundle, federation-api absent) fails the whole
     * {@code save} with the row UNTOUCHED — the user sees an error AND their profile
     * is still private. The previous order (save, then publish) committed
     * {@code visibility='public'} and only then discovered the publish was refused:
     * the caller got an HTTP error while the database had ALREADY gone public, so the
     * UI showed "could not save" and the next page load read back {@code public}. That
     * is a privacy-relevant lie, not just a confusing message. See
     * {@link #syncVanityUnpublish} for why the UNPUBLISH leg keeps the opposite order.
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
        // A vanity SUBDOMAIN is literally a DNS label, so it cannot be granted without a
        // username to make it out of. Fail CLOSED with the real reason rather than
        // persisting vanity_subdomain_enabled=true with a NULL vanity_username (an
        // inconsistent row) and silently skipping the federation publish. This fires when
        // the caller's token carries no usable Casdoor login name — see
        // {@link ProfileController#usernameOf}, which returns null rather than handing on a
        // composite account id or an email address.
        if (wantsVanity && (username == null || username.isBlank())) {
            return Mono.error(ApiException.badRequest(
                    "no username on the caller's token — a vanity subdomain needs a Casdoor "
                            + "login name to use as its DNS label"));
        }
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
        String normalizedUsername = normalize(username);
        if (wantsVanity && wantsPublic && normalizedUsername != null) {
            // PUBLISH-THEN-PERSIST (see the method Javadoc): the cross-service leg that can
            // refuse runs first, so a refusal leaves user_profile exactly as it was.
            // repo.save() returns the SAME instance it was handed, so publishing with
            // owned.displayName() sends byte-identical bytes to what the post-save order did.
            return federation.publishVanity(normalizedUsername, owned.displayName())
                    .then(repo.save(owned, domain));
        }
        return repo.save(owned, domain)
                .flatMap(saved -> syncVanityUnpublish(normalizedUsername).thenReturn(saved));
    }

    /**
     * The UNPUBLISH half of the vanity sync — fires on every save that is NOT
     * {@code vanitySubdomainEnabled && visibility=='public'} (the PUBLISH half is
     * inlined in {@link #save(String, String, UserProfile, String)} itself, because it
     * must run BEFORE the local write; see that method's Javadoc). No-ops when no
     * username was threaded through (the back-compat
     * {@link #save(String, UserProfile)} overload — there is no vanity DNS label to
     * sync against, matching its documented pre-existing contract), and no-ops for a
     * caller whose token carries no usable Casdoor login name at all.
     *
     * <p><b>Why this leg keeps the opposite order (persist, THEN unpublish) and is
     * BEST-EFFORT:</b> it fires on EVERY non-public save, most of which never touched
     * vanity — an unrelated pronoun/timezone edit must not 500 because federation-api
     * is unreachable. And the failure direction is benign: the durable local row is
     * already correctly PRIVATE the moment the save completes, so the worst outcome is
     * a lagging federation fragment that converges on the next successful sync. The
     * publish leg's failure direction is the opposite (a row that went public when the
     * user was told it did not), which is why only that one is ordered-first and
     * hard-failing.
     *
     * @param normalizedUsername the lower-cased vanity username, or {@code null} when
     *                           none was threaded through this save
     */
    private Mono<Void> syncVanityUnpublish(String normalizedUsername) {
        if (normalizedUsername == null || normalizedUsername.isBlank()) {
            return Mono.empty();
        }
        return federation.unpublishVanity(normalizedUsername)
                .onErrorResume(e -> {
                    log.warn("[vanity] best-effort unpublish sync failed for {}: {}",
                            normalizedUsername, e.toString());
                    return Mono.empty();
                });
    }

    /** Lower-cased/trimmed username — mirrors {@link UserProfile#withVanityUsername}'s
     *  normalization so the federation sync target always matches what was (or would
     *  have been) persisted as {@code vanity_username}. {@code null}/blank in, {@code
     *  null} out. */
    private static String normalize(String username) {
        return (username == null || username.isBlank()) ? null : username.trim().toLowerCase();
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
     * {@code owner} is the JWT SUBJECT (owner enforcement — a user can only ever
     * change their own password); {@code username} is the caller's Casdoor USERNAME,
     * derived by the controller from the validated token's {@code preferred_username}
     * claim ({@link ProfileController#usernameOf}).
     *
     * <p>THE TWO ARE NEVER THE SAME VALUE in this platform: the subject is the
     * Casdoor UUID on a real Casdoor JWT and the composite {@code provider:handle}
     * account id on a bff_-session synthetic principal — Casdoor's
     * {@code /api/set-password} addresses users by {@code <org>/<username>}, so
     * sending the subject made every live change fail with "user doesn't exist"
     * (and the pre-fix client swallowed that failure into a success ack).
     */
    public Mono<Void> changePassword(String owner, String username, String oldPassword, String newPassword) {
        requireOwner(owner);
        requireUsername(username);
        if (newPassword == null || newPassword.isBlank()) {
            return Mono.error(ApiException.badRequest("newPassword required"));
        }
        return casdoor.changePassword(username, oldPassword, newPassword);
    }

    /** Self-service email change → Casdoor IdP (the caller's own identity).
     *  {@code owner}/{@code username} split exactly as {@link #changePassword}. */
    public Mono<Void> changeEmail(String owner, String username, String newEmail) {
        requireOwner(owner);
        requireUsername(username);
        if (newEmail == null || newEmail.isBlank()) {
            return Mono.error(ApiException.badRequest("email required"));
        }
        return casdoor.changeEmail(username, newEmail);
    }

    /** Whether the live Casdoor account write is wired (vs. the documented stub). */
    public boolean casdoorEnabled() { return casdoor.enabled(); }

    /**
     * The Casdoor username is the ADDRESS of the IdP write — fail closed (never fall back
     * to the subject: that is the exact defect this split fixed).
     *
     * <p>Rejects BLANK and, since it is an address and not free text, anything that cannot
     * BE a Casdoor username: a value bearing {@code ':'} is the composite
     * {@code provider:handle} account id of a {@code bff_} session (Casdoor answers
     * {@code "The user hugmesh/google:alice@example.com doesn't exist"}), and a value bearing
     * {@code '@'} is an email address — Casdoor forbids {@code '@'} in a username outright
     * (see {@code CasdoorAdminClient.usernameOf}). {@link ProfileController#usernameOf}
     * already filters both, so in the wired flow this is DEFENCE IN DEPTH: it is the guard
     * that holds if a future carrier ever hands on a raw handle or subject again, which is
     * precisely how the original subject-as-username defect came back for the {@code bff_}
     * session principal after being fixed for the JWT one. The old guard checked only
     * null/blank and so waved every composite through.
     */
    private static void requireUsername(String username) {
        if (username == null || username.isBlank()) {
            throw ApiException.badRequest("no Casdoor login name on the caller's token "
                    + "— cannot address the IdP account. A federated or email-keyed session "
                    + "carries no recoverable Casdoor username; sign in natively to change "
                    + "your password or email.");
        }
        if (username.indexOf(':') >= 0 || username.indexOf('@') >= 0) {
            throw ApiException.badRequest("'" + username + "' is not a Casdoor login name "
                    + "(it is an account id or an email address) — refusing to address the "
                    + "IdP account with it");
        }
    }

    private static void requireOwner(String owner) {
        if (owner == null || owner.isBlank()) {
            throw ApiException.unauthorized("missing authenticated subject");
        }
    }
}
