package systems.snapdragon.userbff.auth;

import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Mono;
import systems.snapdragon.userbff.hsproxy.ServiceTokenBroker;

import java.util.Locale;

/**
 * THE single, shared homeserver-identity resolver -- the ONE place the account-takeover-by-
 * collision policy is defined for every {@code /bff/user/**} call site that needs the caller's
 * canonical Matrix/Mastodon localpart (the two D6 reverse-proxy MINT sites, the media-custody
 * MINT, the self-silence hide seams, and the connected-clients read/gateway-revoke). Five
 * controllers plus the sticker-pack service each used to carry a byte-for-byte copy of this
 * logic; this bean deletes those copies so the decision can never drift between sites.
 *
 * <h3>The policy (in order)</h3>
 * <ol>
 *   <li><b>Claim-first (the native-login / {@code bff_}-session path).</b> When the principal is
 *       the SYNTHETIC {@link Jwt} {@code BffSessionAuthenticationWebFilter} builds, it already
 *       carries {@code localpart} / {@code mastodon_localpart} claims stamped from admin-bff's
 *       PERSISTED, collision-checked {@code account.localpart} / {@code account.mastodon_localpart}
 *       (Liquibase changesets 290/291). Those claims are used VERBATIM -- no admin-bff hop, and the
 *       {@code mastodon_localpart} value is admin-bff's own fold, NEVER a client-side re-fold of
 *       {@code localpart}.</li>
 *   <li><b>Own-{@code casdoor:}-key resolution (a REAL Casdoor JWT presented DIRECTLY).</b> A
 *       validly-signed Casdoor access token presented straight to these resource-server routes
 *       never passes through {@code BffSessionAuthenticationWebFilter}, so it carries NO localpart
 *       claim. We resolve the caller's OWN account by the SAME key admin-bff persisted it under:
 *       {@code idFor("casdoor", subject)} where {@code subject} is the first non-blank of
 *       {@code {email, preferred_username, sub}} -- mirroring admin-bff's
 *       {@code InternalAccountController.subjectFromIdToken} ({@code SUBJECT_CLAIMS}) +
 *       {@code AccountStore.idFor(provider, handle) = provider + ":" + handle.toLowerCase()}.
 *       The persisted {@code localpart} / {@code mastodonLocalpart} on that account view is then
 *       returned.</li>
 *   <li><b>Fail closed.</b> No identity claim, no registered {@code casdoor:} account for the
 *       caller's OWN subject, admin-bff unreachable, or an account with no persisted localpart yet
 *       =&gt; the strict methods ERROR ({@code 401}/{@code 409}); the mint never fires. There is NO
 *       fall back to a raw cross-namespace guess.</li>
 * </ol>
 *
 * <h3>Why the OLD code was exploitable</h3>
 * The deleted copies resolved, for a real Casdoor JWT, {@code email -> google:<email>} else
 * {@code preferred_username -> discord:<preferred_username>}. "Discord federation" is only an
 * admin-invite allowlist keyed on a SELF-REPORTED username, and a real Casdoor JWT carries no
 * {@code provider}/{@code idp} claim while seeded users carry {@code email:""} -- so execution
 * fell to {@code preferred_username -> discord:<pu>}, resolving a DIFFERENT person's invite
 * account and minting a homeserver token under the VICTIM's persisted localpart: cross-user
 * account takeover. Resolving the holder's OWN {@code casdoor:} key closes the class entirely --
 * a JWT holder can NEVER resolve an account in a provider-namespace it does not own.
 */
@Component
public class CanonicalIdentityResolver {

    /** The claim {@code BffSessionAuthenticationWebFilter.syntheticJwt} stamps from the persisted
     *  Matrix {@code account.localpart} (changeset 290). */
    static final String CLAIM_LOCALPART = "localpart";
    /** The claim stamped from the persisted Mastodon fold {@code account.mastodon_localpart}
     *  (changeset 291) -- its OWN uniqueness, never a re-fold of {@link #CLAIM_LOCALPART}. */
    static final String CLAIM_MASTODON_LOCALPART = "mastodon_localpart";

    /** The provider namespace every native-login account is keyed under (the login provider,
     *  not an invite provider). */
    static final String CASDOOR = "casdoor";

    /** The subject-claim precedence admin-bff's {@code InternalAccountController.SUBJECT_CLAIMS}
     *  uses when it derives the stable {@code casdoor:<subject>} account key at account-creation.
     *  Mirrored EXACTLY here so the lookup key equals the persisted key. */
    static final String[] SUBJECT_CLAIMS = {"email", "preferred_username", "sub"};

    private final AdminBffInternalClient adminBff;

    public CanonicalIdentityResolver(AdminBffInternalClient adminBff) {
        this.adminBff = adminBff;
    }

    // -- strict (homeserver-MINT / custody / gateway-revoke) -- FAIL CLOSED ---------------

    /**
     * The caller's canonical, persisted Matrix localpart. Claim-first, else the caller's OWN
     * {@code casdoor:} account's {@code localpart}. ERRORS ({@code 401} no own account /
     * {@code 409} no persisted localpart yet) rather than ever deriving an unchecked candidate --
     * the mint/custody/gateway-revoke call sites depend on this failing closed.
     */
    public Mono<String> matrixLocalpart(Jwt jwt) {
        String claim = jwt.getClaimAsString(CLAIM_LOCALPART);
        if (claim != null && !claim.isBlank()) {
            return Mono.just(claim);
        }
        return resolveOwnAccount(jwt).flatMap(a -> requireLocalpart(a.localpart()));
    }

    /**
     * The caller's canonical, persisted Mastodon localpart. Claim-first ({@code mastodon_localpart}),
     * else the caller's OWN {@code casdoor:} account's persisted Mastodon fold; when that account
     * predates changeset 291 (blank Mastodon fold) the persisted MATRIX localpart is folded via
     * {@link ServiceTokenBroker#mastodonLocalpart} (the transitional path, so a rollout where
     * user-bff leads admin-bff never breaks Mastodon minting). FAIL CLOSED when even the Matrix
     * localpart is unresolved.
     */
    public Mono<String> mastodonLocalpart(Jwt jwt) {
        String claim = jwt.getClaimAsString(CLAIM_MASTODON_LOCALPART);
        if (claim != null && !claim.isBlank()) {
            return Mono.just(claim);
        }
        return resolveOwnAccount(jwt).flatMap(CanonicalIdentityResolver::mastodonFrom);
    }

    // -- best-effort (self-silence hide seams) -- DEGRADE to "" ---------------------------

    /**
     * Best-effort Matrix localpart for the self-silence hide seams: identical resolution to
     * {@link #matrixLocalpart}, but any miss/failure degrades to {@code ""} (the caller's own
     * self-silence activate/cancel must never fail on an unresolved directory-hide identity -- the
     * hide is documented best-effort + gated, and {@code SelfSilenceService} skips a blank leg).
     */
    public Mono<String> matrixLocalpartOrBlank(Jwt jwt) {
        return matrixLocalpart(jwt).onErrorResume(e -> Mono.just("")).defaultIfEmpty("");
    }

    /** Best-effort Mastodon localpart for the self-silence hide seams -- see
     *  {@link #matrixLocalpartOrBlank}. */
    public Mono<String> mastodonLocalpartOrBlank(Jwt jwt) {
        return mastodonLocalpart(jwt).onErrorResume(e -> Mono.just("")).defaultIfEmpty("");
    }

    // -- subject-only (sticker-pack registration -- NO JWT in context) --------------------

    /**
     * The owner's canonical, persisted Matrix localpart resolved from a bare owner SUBJECT string
     * (the sticker-pack registration runs under {@code ROLE_SERVICE} off the moderation loop -- there
     * is NO caller JWT, only the {@code ownerSubject} the creating controller stamped onto the
     * sticker row from its OWN validated {@code jwt.getSubject()}).
     *
     * <p>The stamped subject is EITHER a full account id ({@code casdoor:<uuid>} / {@code
     * google:<email>} -- the native-login synthetic principal's {@code sub} IS the account id) or a
     * bare Casdoor subject (a real Casdoor JWT's raw {@code sub}); the former is looked up verbatim,
     * the latter normalised to {@code casdoor:<subject>}. Returns the owner's OWN persisted {@code
     * localpart}. Completes EMPTY -- never a raw derivation -- on a blank subject, no such account, a
     * blank localpart, or an admin-bff failure, so the caller mints NOTHING (fail closed: the
     * previous {@code ServiceTokenBroker.localpart(ownerSubject)} fallback was the exact takeover
     * vector on this leg).
     */
    public Mono<String> ownMatrixLocalpartForSubject(String subject) {
        String id = ownAccountId(subject);
        if (id == null) {
            return Mono.empty();
        }
        return adminBff.getAccount(id)
                .map(AdminBffInternalClient.AccountView::localpart)
                .filter(lp -> !lp.isBlank())
                .onErrorResume(e -> Mono.empty());
    }

    // -- own account id (for consumers that need the id itself, not a localpart) -----------

    /**
     * The caller's OWN account id, mirroring the key admin-bff persisted -- for consumers that
     * need the id itself (e.g. {@code SessionsService}), not a homeserver localpart. Claim-derived,
     * NEVER a cross-namespace guess: {@code subject} = first non-blank of {@link #SUBJECT_CLAIMS};
     * a subject that already looks like a full account id (contains {@code ':'} -- e.g. the bff_
     * synthetic principal's {@code sub}, which IS {@code provider:handle} for EVERY provider) is
     * used verbatim, else it is normalised to {@code casdoor:<subject>}. {@code null} when the JWT
     * carries no usable identity claim.
     */
    public static String ownAccountId(Jwt jwt) {
        return ownAccountId(subjectOf(jwt));
    }

    /** Subject-string overload of {@link #ownAccountId(Jwt)} -- the shared account-id derivation
     *  (also used by {@link #ownMatrixLocalpartForSubject}). */
    static String ownAccountId(String subject) {
        if (subject == null || subject.isBlank()) {
            return null;
        }
        return subject.contains(":") ? subject : idFor(CASDOOR, subject);
    }

    // -- internals ------------------------------------------------------------------------

    /**
     * Resolve the caller's OWN account view by its {@code casdoor:<subject>} key, FAIL CLOSED:
     * a {@code 404} (no such account) or an absent identity claim ERRORS {@code 401}; any other
     * admin-bff error propagates unchanged (still "no mint"). NEVER resolves a foreign
     * provider-namespace account -- the whole point of the fix.
     */
    private Mono<AdminBffInternalClient.AccountView> resolveOwnAccount(Jwt jwt) {
        String subject = subjectOf(jwt);
        if (subject == null) {
            return Mono.error(new ResponseStatusException(HttpStatus.UNAUTHORIZED,
                    "no identity claim on token (email/preferred_username/sub all absent) -- "
                            + "cannot resolve the caller's own account (fail-closed)"));
        }
        return adminBff.getAccount(idFor(CASDOOR, subject))
                .onErrorResume(WebClientResponseException.NotFound.class, e -> Mono.empty())
                .switchIfEmpty(Mono.error(new ResponseStatusException(HttpStatus.UNAUTHORIZED,
                        "no registered account for this token's OWN identity "
                                + "(fail-closed homeserver-localpart resolution)")));
    }

    /** First non-blank of {@link #SUBJECT_CLAIMS}, mirroring admin-bff's account-key derivation
     *  ({@code sub} is read via the same claim so a real access token and the id_token that
     *  created the account agree when both carry it).
     *
     *  <p>TODO(#124 residual, unverified offline): this assumes a real Casdoor ACCESS token
     *  carries the same {@code email}/{@code preferred_username} claims the ID token carried
     *  when admin-bff derived the account's {@code casdoor:<subject>} key at creation time. If
     *  the access token carries a narrower claim set (e.g. only {@code sub}), this lookup could
     *  miss for an existing account and fail closed — an availability regression, not a
     *  security one (see the PR body / README "Known gaps"). Needs confirming against a live
     *  Casdoor token capture before this can be crossed off. */
    private static String subjectOf(Jwt jwt) {
        for (String claim : SUBJECT_CLAIMS) {
            String v = jwt.getClaimAsString(claim);
            if (v != null && !v.isBlank()) {
                return v;
            }
        }
        return null;
    }

    /** {@code AccountStore.idFor(provider, handle) = provider + ":" + handle.toLowerCase()} --
     *  the persisted account-id format. {@code trim()}/{@link Locale#ROOT} match this repo's own
     *  {@code idFor} convention and are byte-identical to admin-bff's derivation for the ASCII,
     *  no-whitespace subjects (emails / UUIDs / usernames) these keys are made of. */
    static String idFor(String provider, String subject) {
        return provider + ":" + subject.trim().toLowerCase(Locale.ROOT);
    }

    private static Mono<String> requireLocalpart(String lp) {
        return (lp == null || lp.isBlank())
                ? Mono.error(new ResponseStatusException(HttpStatus.CONFLICT,
                        "account has no persisted homeserver localpart yet "
                                + "(fail-closed -- will not re-derive an unchecked candidate)"))
                : Mono.just(lp);
    }

    private static Mono<String> mastodonFrom(AdminBffInternalClient.AccountView a) {
        String mastodon = a.mastodonLocalpart();
        if (mastodon != null && !mastodon.isBlank()) {
            return Mono.just(mastodon);
        }
        String matrix = a.localpart();
        return (matrix == null || matrix.isBlank())
                ? Mono.error(new ResponseStatusException(HttpStatus.CONFLICT,
                        "account has no persisted homeserver localpart yet "
                                + "(fail-closed -- will not re-derive an unchecked candidate)"))
                : Mono.just(ServiceTokenBroker.mastodonLocalpart(matrix));
    }
}
