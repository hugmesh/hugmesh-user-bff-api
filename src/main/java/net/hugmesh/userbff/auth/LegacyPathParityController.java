package net.hugmesh.userbff.auth;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import net.hugmesh.authcore.config.SessionCookieService;
import net.hugmesh.authcore.reserved.ReservedNames;
import net.hugmesh.authcore.web.dto.RegisterDiscordRequest;
import net.hugmesh.authcore.web.dto.RegisterEmailRequest;
import net.hugmesh.commons.web.ApiException;
import net.hugmesh.userbff.hsproxy.HsTokenCustody;
import net.hugmesh.userbff.hsproxy.MintedToken;
import net.hugmesh.userbff.hsproxy.ServiceTokenBroker;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * PARITY handlers for three of the five legacy {@code AuthController} user paths that
 * hugmesh-admin-bff-api still serves but that the CLUSTER gateway already routes here —
 * {@code GET /bff/me/namespaces}, {@code POST /bff/provision/matrix} and
 * {@code POST /bff/provision/mastodon}.
 *
 * <h2>Why this class exists</h2>
 *
 * <p>Operator decision 25 on hugmesh/hugmesh-generator#347 (2026-09-16): <b>"Parity first,
 * then retire."</b> The three-lane audit on hugmesh/hugmesh-admin-bff-api#2 measured that
 * the deployed cluster ConfigMap {@code hugmesh-frontend/hugmesh-fe-gateway-routes} declares
 * {@code Path=/bff/me/**} and {@code Path=/bff/provision/**} to user-bff BEFORE the
 * {@code /bff/**} admin-bff catch-all, and Spring Cloud Gateway matches in declared order —
 * so these three paths resolve to user-bff, which implemented NONE of them. <b>They 404 on a
 * cluster today.</b> (On the compose lane and on device images the same paths still reach
 * admin-bff's {@code AuthController}; those lanes are unaffected by this class until the
 * generator's route tables are aligned — hugmesh/hugmesh-generator#366.)
 *
 * <p><b>Nothing is retired here.</b> admin-bff keeps serving all eleven of its mappings; this
 * class only stops the cluster 404. Deleting from admin-bff is a LATER slice and only once
 * every caller is proven served (see hugmesh-admin-bff-api#2).
 *
 * <h2>Contract parity with admin-bff's {@code AuthController}, path by path</h2>
 *
 * <table border="1">
 *   <caption>status codes</caption>
 *   <tr><th>condition</th><th>admin-bff</th><th>here</th></tr>
 *   <tr><td>no session / no JWT</td><td>401</td><td>401</td></tr>
 *   <tr><td>missing ROLE_MATRIX / ROLE_MASTODON</td><td>403 ({@code @PreAuthorize})</td>
 *       <td>403 ({@code @PreAuthorize})</td></tr>
 *   <tr><td>registration not complete</td><td>403 "complete registration first"</td>
 *       <td>403 "complete registration first"</td></tr>
 *   <tr><td>reserved localpart</td><td>400</td><td>400</td></tr>
 *   <tr><td>no persisted localpart / collision</td><td>409</td><td>409</td></tr>
 *   <tr><td>homeserver mint failed</td><td>502</td><td>502</td></tr>
 *   <tr><td>brokering not configured</td><td>(no such gate)</td><td>503 — see below</td></tr>
 * </table>
 *
 * <h2>The DELIBERATE divergences, and why each one is not a regression</h2>
 *
 * <ol>
 *   <li><b>The provision response body carries NO {@code access_token}.</b> admin-bff returns
 *       the raw broker map ({@code access_token}, {@code user_id}, …) to the browser. user-bff
 *       is the D6 architecture: a minted homeserver token is {@link MintedToken} — IN-PROCESS
 *       ONLY, encrypted into the {@link HsTokenCustody} store and injected server-side by the
 *       {@code /bff/user/{matrix,mastodon}/**} reverse proxies; the browser holds no homeserver
 *       credential at all. Emitting the token here would reverse that, which is a security
 *       property the operator did not ask to flip. <b>No caller reads the body:</b>
 *       hugmesh-login-ui's {@code provisionServiceTokens()} says in its own comment "the
 *       returned access_token is intentionally discarded" and {@code .catch(() =&gt; undefined)}s
 *       the call; hugmesh-generator's {@code tests/stack/seed-e2e.sh:544-551} branches on the
 *       HTTP status only; and the generator's own {@code tests/stack/mock-bff.mjs:318-326}
 *       already answers these two paths with exactly {@code {"ok": true}} — which is therefore
 *       the shape this returns.</li>
 *   <li><b>The custody/brokering fail-closed 503.</b> admin-bff has no feature gate on
 *       {@code /provision/*}. user-bff's mint physically cannot complete without
 *       {@code app.hs-token.enabled} and a custody cipher key, so this mirrors
 *       {@code MatrixProxyController}/{@code MastodonProxyController}'s existing fail-closed
 *       503 rather than inventing a fourth posture. A cluster that runs the D6 proxies at all
 *       has both set, so the 503 is unreachable there.</li>
 *   <li><b>Identity resolution for a RAW Casdoor JWT carrier.</b> admin-bff's
 *       {@code accountFromJwt} resolves {@code email → google:<email>} else
 *       {@code preferred_username → discord:<preferred_username>}. That is precisely the
 *       cross-namespace lookup {@link CanonicalIdentityResolver}'s class doc documents as the
 *       account-takeover vector it was created to delete. This class uses the resolver instead,
 *       so a raw Casdoor JWT resolves the caller's OWN {@code casdoor:<subject>} account and
 *       never a foreign provider-namespace one. Reproducing admin-bff's JWT branch would re-open
 *       a closed takeover class.
 *
 *       <p><b>On the {@code bff_} carrier — the only one the live callers use — the two agree,
 *       but ONLY because {@link CanonicalIdentityResolver#ownAccountId(Jwt)} branches on the
 *       synthetic-principal marker.</b> An earlier revision of this class claimed the two
 *       resolutions were identical on that carrier "because the synthetic {@code sub} IS the
 *       account id". That reasoning was WRONG and the claim was false: {@code SUBJECT_CLAIMS}
 *       reads {@code email} and {@code preferred_username} BEFORE {@code sub}, and
 *       {@code BffSessionAuthenticationWebFilter.syntheticJwt} always stamps one of them with
 *       the bare HANDLE, so the derivation never reached the {@code sub} at all. MEASURED
 *       against a principal built exactly as that filter builds it: a {@code google:} session
 *       asked admin-bff for {@code casdoor:alice@example.test} and every one of these three
 *       paths answered {@code 401 {"error":"login required"}}; a {@code discord:} session the
 *       same; only a {@code casdoor:} session worked, which is why a cluster holding only
 *       {@code casdoor:} rows would not have shown it. The resolver now honours the synthetic
 *       {@code sub} verbatim for EVERY provider — see its own javadoc — and
 *       {@code LegacyPathParityControllerTest} pins all three namespaces.</li>
 *   <li><b>No self-heal of a blank persisted localpart.</b> admin-bff's {@code provision} calls
 *       {@code AccountLocalpartService.resolveAndPersist} when {@code account.localpart} is
 *       blank and then mints; user-bff owns no account table, so {@link
 *       CanonicalIdentityResolver} FAILS CLOSED instead — 409 on a raw Casdoor JWT carrier, and
 *       on a {@code bff_} carrier 409 for a {@code casdoor:} account but 401 for a
 *       {@code google:}/{@code discord:} one, because the resolver's {@code resolveOwnAccount}
 *       branch (taken only when the {@code localpart} claim is absent) still derives its key
 *       from {@code SUBJECT_CLAIMS}. That residual asymmetry is filed as
 *       hugmesh-user-bff-api#14 and deliberately NOT closed here — {@code resolveOwnAccount} is
 *       shared by five other mint/custody/revoke call sites, so re-pointing it is a change to
 *       the shared identity policy rather than a parity fix. Both outcomes are fail-closed
 *       refusals with no mint down either branch, and both are pinned in
 *       {@code LegacyPathParityControllerTest}. Unreachable on the cluster lane in practice:
 *       {@code POST /bff/login} routes here and its {@code ensureAccount} hop makes admin-bff
 *       persist the localpart on EVERY sign-in, so a caller holding a session holds a
 *       localpart.</li>
 *   <li><b>Gate ORDER: the brokering 503 is evaluated before the registration-complete
 *       check.</b> admin-bff has no brokering gate at all, so on a deploy with
 *       {@code app.hs-token.enabled=false} an incomplete-registration caller gets 503 here where
 *       admin-bff gives 403 "complete registration first". Deliberate: the 503 is a pure local
 *       constant-check and running it first avoids an admin-bff round trip that cannot change
 *       the answer. Reachable only for a RAW Casdoor JWT carrier on a dark deploy — a
 *       {@code bff_} caller with an incomplete registration has already been 403'd by
 *       {@code @PreAuthorize}, because the filter strips every role but the {@code ROLE_USER}
 *       floor from such an account.</li>
 *   <li><b>ReservedNames input on the Mastodon leg.</b> admin-bff applies
 *       {@code ReservedNames.isReserved} to the MATRIX username on BOTH legs and never to the
 *       Mastodon fold ({@code AuthController} lines 456-465); this class checks the fold each leg
 *       actually mints under. The two differ only for a handle whose Matrix and Mastodon folds
 *       disagree about reservedness — user-bff is stricter in one direction (a reserved Mastodon
 *       fold 400s where admin-bff mints) and looser in the other. This is defence-in-depth on
 *       both sides: registration already refuses a reserved handle. Checking the value actually
 *       being minted is the behaviour worth keeping, so it is declared rather than "fixed"
 *       towards admin-bff's.</li>
 *   <li><b>CSRF posture.</b> admin-bff requires a CSRF token for these cookie-carried, non-mint
 *       mutations when its cookie mode is on ({@code SecurityConfig.cookieCsrfMatcher}; the
 *       exempt set is {@code /bff/login}, {@code /bff/login/local}, {@code /bff/sessionOut},
 *       {@code /bff/register/**} — provision is NOT exempt), and login-ui sends the header
 *       accordingly. user-bff disables CSRF on BOTH chains and accepts the {@code bff_session}
 *       cookie as a carrier, so moving these POSTs here moves them to that posture. NOT a choice
 *       this class makes — it is user-bff's pre-existing org-wide posture, which every other
 *       mutating user-bff endpoint already rides — and not practically exploitable: the session
 *       cookie is {@code SameSite=Lax}, so a cross-site POST never carries it, and
 *       {@code APP_SESSION_COOKIE_ENABLED} defaults false. Declared here because a divergence
 *       list that omits it is not exhaustive.</li>
 * </ol>
 *
 * <h2>The two REGISTER paths: what is reproduced, what is ruled, what is recorded</h2>
 *
 * <p>{@code POST /bff/register/google} and {@code POST /bff/register/discord} were held back
 * from the first revision of this class. Operator decision 40 (hugmesh-generator#347,
 * 2026-09-17) then aligned the COMPOSE route table onto user-bff as well, so from that commit
 * both paths 404 on BOTH lanes — the generator's own route file calls it "a deliberate,
 * accepted regression for two of them". They are served here now.
 *
 * <p>admin-bff's {@code AuthController#registerGoogle}/{@code registerDiscord} do six things.
 * user-bff does four of them over the existing {@code /bff/internal/**} surface:
 * {@code allowlistCheck} is the invite gate; {@code ensureAccount} both creates the row AND
 * persists the collision-checked localpart (admin-bff's {@code InternalAccountController
 * #ensureAccount} runs {@code withLocalpart} itself, so the 409 comes back over the wire);
 * {@code createSession} mints the opaque {@code bff_} token; the cookie is minted here.
 * The remaining two are the subject of two operator rulings on hugmesh-generator#347
 * (2026-09-18, decisions 55 and 57):
 *
 * <ol>
 *   <li><b>{@code AccountStore.restartOnboarding(a)} — RULED, not reproduced: 409 (decision
 *       57).</b> It is {@code setComplete(a, false)} and nothing else (auth-core
 *       {@code AccountStore:259-272}) and matters on exactly ONE input: a RE-registration of an
 *       account that is ALREADY {@code registrationComplete}. A fresh registration creates the
 *       row with {@code false} and a re-registration of an incomplete account leaves it
 *       {@code false} ({@code ensureAccount} preserves {@code existing.registrationComplete()}),
 *       so on every other input {@code restartOnboarding} is a no-op and this class is exact
 *       parity. admin-bff's {@code /bff/internal/**} surface still exposes nothing that can set
 *       {@code registration_complete} back to FALSE (hugmesh-admin-bff-api#84, open; measured
 *       on admin-bff {@code origin/main} {@code 86cdf79}). <b>On that one input this class
 *       answers {@code 409 Conflict}</b> — the registration conflicts with an account that
 *       already exists and has completed onboarding — leaves the account untouched, mints no
 *       session and records no usage row; the caller can sign in at {@code POST /bff/login}.
 *       Decision 57 chose 409 over the recommended "503 until #84 lands" (the 503 this class
 *       carried between 2026-09-18 and this revision) and over holding the handlers. It is a
 *       RULING, so this class does not promise that #84 replaces it; if the operator later
 *       wants the restart reproduced, that is a new decision. Two things follow from it that a
 *       caller can see: (a) admin-bff's own {@code AuthController} would instead reset the
 *       account, mint a session AND record a {@code "register"} usage row for that input — the
 *       usage-table divergence is declared under (2); (b) this 409 shares a status with the
 *       localpart-collision 409 raised in {@link #asInternalHopFailure}, so its body names
 *       "already completed registration" and decision 57 explicitly, and the tests assert on
 *       the message rather than the status alone.</li>
 *   <li><b>{@code UsageService.record(handle, roles, "register")} — RECORDED over the wire
 *       (decision 55 = yes).</b> admin-bff's {@code emitAndSession} fires it as
 *       {@code usage.record(handle, a.roles(), action).subscribe()} — fire-and-forget, BEFORE
 *       the session mint, with the BARE handle (the lowercased email/username, not the
 *       {@code provider:handle} id) and the account's own lowercase {@code roles}. Since
 *       hugmesh-admin-bff-api PR #104 ({@code 86cdf79}) that call is reachable as
 *       {@code POST /bff/internal/usage}, and {@link #register} calls it through
 *       {@link AdminBffInternalClient#recordUsage} at the SAME point in the chain with the SAME
 *       three arguments, and with the SAME semantics: subscribed detached from the response,
 *       so a usage outage (admin-bff 5xx, a dropped connection, the produce blocking on
 *       {@code max.block.ms}) is logged and never delays or fails the registration. The
 *       roles list is forwarded VERBATIM from {@link AdminBffInternalClient.AccountView#roles()}
 *       because that IS admin-bff's lowercase dialect; prefixing {@code ROLE_} here would make
 *       admin-bff tag every event {@code user}. <b>The declared divergence:</b> the row is
 *       recorded only when a registration is PERFORMED, i.e. on the success path; on the
 *       already-complete input admin-bff records a {@code "register"} row and this class,
 *       having refused with 409 under decision 57, records nothing. Not a dependency on #84:
 *       the usage call sits after the already-complete gate, so whatever that gate does the
 *       leg is unchanged.</li>
 * </ol>
 *
 * <h3>The register legs' OTHER declared divergences</h3>
 *
 * <ol>
 *   <li><b>No profile forward.</b> admin-bff calls {@code forwardProfile(a, displayName,
 *       screenReaderName)}. Its {@code ProfileForwarder}'s user-bff leg is gated on
 *       {@code profile.forward.enabled} (default FALSE) and its own javadoc says the user-bff
 *       internal upsert "is wired in the deployment once the user-bff exposes the internal
 *       upsert; until then the seam stays gated off" — user-bff exposes no such endpoint
 *       ({@code ProfileController} is {@code /bff/user/profile}, owner-scoped and
 *       authenticated). The independent Casdoor {@code display_name} leg needs
 *       {@code casdoor.admin.enabled}. Writing the profile from here would mean driving
 *       {@code ProfileService.save} (moderation + Casdoor sync + vanity-collision checks) from
 *       a PRE-AUTH mutating handler, which is a new behaviour rather than a parity fix. The
 *       names are accepted in the body (unchanged DTOs) and dropped, exactly as a deployment
 *       with the gate off already drops them.</li>
 *   <li><b>The response body carries no {@code status}/{@code until}/{@code reason}.</b>
 *       admin-bff's {@code sessionOut} folds in {@code suspensions.statusFor(a.handle())}.
 *       This emits the SAME body user-bff's own {@code POST /bff/register}
 *       ({@code SsoAuthController#emitAndSession}) already emits — {@code token}, {@code id},
 *       {@code provider}, {@code registrationComplete}, {@code roles} — so the two register
 *       surfaces of this BFF agree with each other. Reaching admin-bff's suspension view would
 *       cost a second internal hop ({@code /session/introspect}) on a pre-auth path and still
 *       not carry {@code until}/{@code reason}, which that body does not contain. No caller
 *       reads it: hugmesh-login-ui never calls these two paths at all (its {@code bff.service.ts}
 *       comment: "the Casdoor account itself is created server-side by user-bff during
 *       login/loginLocal, not by a client-initiated register call"), and the one script caller,
 *       hugmesh-generator {@code tests/qemu/seed-accounts.sh:408,464}, reads {@code .token}
 *       only.</li>
 *   <li><b>The invite gate's DOMAIN is the deployment's own, never a forwarded token's.</b>
 *       admin-bff resolves it with {@code RegistrationDomainResolver.forRegistration(auth)} —
 *       the {@code app.tenancy.registration-domain} pin, ELSE a trusted forwarded token's
 *       issuer brand, ELSE {@code fallback()}. The internal read this class uses resolves
 *       {@code forInternalCaller(null)} = {@code fallback()} — the pin, else the deployment's
 *       one known brand, else the fail-closed {@code NO_DOMAIN} sentinel. The two therefore
 *       agree on every single-brand or pinned deployment and differ only on an UNPINNED
 *       MULTI-BRAND one where the registering caller attached a trusted JWT: admin-bff would
 *       gate on that token's brand, this fails CLOSED (no allowlist row matches ⇒ 403 "not
 *       invited"). Deliberately not closed by sending a domain: the caller-chosen-domain shape
 *       is the exact hole {@code RegistrationDomainResolver}'s security contract exists to
 *       refuse, and user-bff naming a brand on a pre-auth caller's behalf re-opens it.</li>
 *   <li><b>The 409 wording.</b> A homeserver-localpart collision comes back from the internal
 *       {@code /accounts/ensure} hop as a {@code 409}, which is re-raised as a {@code 409} here
 *       with this class's own message; admin-bff surfaces {@code
 *       AccountLocalpartService.CollisionException}'s text. Same status, different prose —
 *       admin-bff's body is not forwarded because it is an internal-hop payload.</li>
 *   <li><b>The DARK posture is 500, not 503.</b> With {@code app.bff.oidc.enabled=false} the
 *       {@link AdminBffInternalClient} is a fail-closed stub whose {@code IllegalStateException}
 *       renders as 500. That is byte-for-byte what user-bff's existing {@code POST /bff/register}
 *       already does on a dark deploy; no new gate is invented here, and no account or session
 *       op is performed. (The {@code /provision/*} legs above DO have a 503 gate — that one
 *       mirrors the D6 proxy controllers' brokering check, which has no analogue on a register
 *       path.)</li>
 *   <li><b>CSRF posture</b> — as for the provision legs above (divergence 7): user-bff disables
 *       CSRF on both chains. admin-bff's exempt set already includes {@code /bff/register/**},
 *       so for THESE two paths the two postures happen to agree.</li>
 * </ol>
 *
 * @see SsoAuthController the OIDC-era login/register/session surface this sits beside
 * @see CanonicalIdentityResolver the single homeserver-identity policy
 */
@Tag(name = "Legacy path parity", description =
        "admin-bff AuthController parity for the cluster-routed legacy user paths "
                + "(/bff/me/namespaces, /bff/provision/matrix, /bff/provision/mastodon, "
                + "/bff/register/google, /bff/register/discord). "
                + "Decision 25 on hugmesh-generator#347: parity first, then retire.")
@RestController
@RequestMapping("/bff")
public class LegacyPathParityController {

    /** The exact body the generator's mock-bff already answers {@code /bff/provision/*} with. */
    private static final Map<String, Object> OK = Map.of("ok", true);

    private static final Logger log = LoggerFactory.getLogger(LegacyPathParityController.class);

    /**
     * The already-complete refusal of {@code /bff/register/*} — operator decision 57 on
     * hugmesh-generator#347 (2026-09-18): a re-registration of an account that has ALREADY
     * completed registration is a {@code 409 Conflict} with that existing account. Worded so
     * it cannot be mistaken for the OTHER 409 on this path (the homeserver-localpart collision
     * in {@link #asInternalHopFailure}), and so the reader knows the account was left untouched.
     */
    private static final String ALREADY_REGISTERED_CONFLICT =
            "this account already exists and has already completed registration "
                    + "(decision 57: 409, not a restart of onboarding). Nothing was changed; "
                    + "sign in at /bff/login instead.";

    /** The {@code action} admin-bff's own register handlers record — {@code AuthController}
     *  passes the literal {@code "register"} to {@code emitAndSession}. */
    private static final String USAGE_ACTION_REGISTER = "register";

    private final AdminBffInternalClient adminBff;
    private final CanonicalIdentityResolver identity;
    private final HsTokenCustody custody;
    private final ServiceTokenBroker broker;
    /** Mints the opaque {@code bff_} session cookie — the same collaborator
     *  {@link SsoAuthController} uses for {@code POST /bff/register}. */
    private final SessionCookieService cookies;
    /** {@code app.hs-token.enabled} — the same gate the D6 proxy controllers read. */
    private final boolean hsTokenEnabled;

    public LegacyPathParityController(AdminBffInternalClient adminBff,
                                      CanonicalIdentityResolver identity,
                                      HsTokenCustody custody,
                                      ServiceTokenBroker broker,
                                      SessionCookieService cookies,
                                      @Value("${app.hs-token.enabled:false}") boolean hsTokenEnabled) {
        this.adminBff = adminBff;
        this.identity = identity;
        this.custody = custody;
        this.broker = broker;
        this.cookies = cookies;
        this.hsTokenEnabled = hsTokenEnabled;
    }

    // ── GET /bff/me/namespaces ────────────────────────────────────────────────────────────

    /**
     * The caller's own granted namespaces — admin-bff {@code AuthController#myNamespaces}
     * parity. Body is {@code {"namespaces": [...]}}, byte-identical to admin-bff's
     * {@code Map.of("namespaces", ns)}; the list is admin-bff's OWN
     * {@code AccountStore.namespacesFor} answer (all namespaces for an admin, the grant rows
     * otherwise), read over the internal surface rather than recomputed here — user-bff holds
     * no {@code namespace_grant} table.
     *
     * <p>{@code operationId} is kept as admin-bff's {@code authMyNamespaces} so an
     * ng-openapi-gen client regenerated against THIS spec keeps the method name
     * hugmesh-admin-ui already calls.
     *
     * <p>401 when the principal carries no usable identity claim, and when admin-bff has no
     * account for it (a 404 on the internal read is mapped to 401 — admin-bff's own
     * {@code me()} answers 401 in exactly that case, not 404).
     */
    @Operation(summary = "The caller's own granted namespaces. admin-bff AuthController parity "
            + "(cluster routes /bff/me/** to user-bff). 401 with no resolvable account.",
            operationId = "authMyNamespaces")
    @GetMapping("/me/namespaces")
    public Mono<Map<String, Object>> myNamespaces(@AuthenticationPrincipal Jwt jwt) {
        return ownAccountId(jwt)
                .flatMap(id -> adminBff.accountNamespaces(id)
                        .onErrorMap(WebClientResponseException.NotFound.class,
                                e -> ApiException.unauthorized("login required")))
                .map(ns -> Map.of("namespaces", (Object) List.copyOf(ns)));
    }

    // ── POST /bff/provision/{matrix,mastodon} ─────────────────────────────────────────────

    /**
     * Broker (or recover) this caller's REAL Matrix homeserver token server-side — admin-bff
     * {@code AuthController#provisionMatrix} parity. The token is encrypted into the custody
     * store and its hash written to the gateway revocation registry by
     * {@link ServiceTokenBroker#mintMatrix}; it is NEVER returned (divergence 1 in the class
     * doc). Answers {@code {"ok": true}}.
     *
     * <p>{@code @PreAuthorize("hasRole('MATRIX')")} mirrors admin-bff's own method-level gate.
     */
    @Operation(summary = "Broker/recover the caller's Matrix homeserver token server-side "
            + "(held in custody; the token is NEVER returned). admin-bff AuthController parity. "
            + "403 without ROLE_MATRIX or before registration is complete; 502 on a mint failure.",
            operationId = "authProvisionMatrix")
    @PreAuthorize("hasRole('MATRIX')")
    @PostMapping("/provision/matrix")
    public Mono<Map<String, Object>> provisionMatrix(@AuthenticationPrincipal Jwt jwt) {
        return provision(jwt, true);
    }

    /**
     * Broker (or recover) this caller's REAL Mastodon/Akkoma homeserver token server-side —
     * admin-bff {@code AuthController#provisionMastodon} parity. See
     * {@link #provisionMatrix(Jwt)}; the localpart is the PERSISTED Mastodon fold
     * ({@code account.mastodon_localpart}, admin-bff changeset 291), never a client-side
     * re-fold of the Matrix localpart.
     */
    @Operation(summary = "Broker/recover the caller's Mastodon homeserver token server-side "
            + "(held in custody; the token is NEVER returned). admin-bff AuthController parity. "
            + "403 without ROLE_MASTODON or before registration is complete; 502 on a mint failure.",
            operationId = "authProvisionMastodon")
    @PreAuthorize("hasRole('MASTODON')")
    @PostMapping("/provision/mastodon")
    public Mono<Map<String, Object>> provisionMastodon(@AuthenticationPrincipal Jwt jwt) {
        return provision(jwt, false);
    }

    /**
     * The shared provision leg, in admin-bff's order: registration-complete gate, canonical
     * localpart, reserved-name guard, mint. Every non-HTTP failure out of the broker becomes a
     * 502 exactly as admin-bff's {@code ApiException.badGateway} wrap does; a broker failure
     * that ALREADY carries a status ({@link ResponseStatusException} — the unconfigured
     * svc-password / mastodon-email-domain 503s) keeps it rather than being masked as 502.
     */
    private Mono<Map<String, Object>> provision(Jwt jwt, boolean matrix) {
        if (!hsTokenEnabled || !custody.cipherAvailable()) {
            // Fail-closed, identical to the D6 proxy controllers: there is no browser-token
            // fallback and a mint cannot be persisted without the custody cipher.
            return Mono.error(ApiException.serviceUnavailable(
                    "homeserver token brokering is not enabled (app.hs-token.enabled=false "
                            + "or no custody key)"));
        }
        return requireCompleteAccount(jwt)
                .then(Mono.defer(() -> matrix ? identity.matrixLocalpart(jwt)
                        : identity.mastodonLocalpart(jwt)))
                .flatMap(localpart -> mintProvisioned(jwt, matrix, localpart))
                .thenReturn(OK);
    }

    /** The {@link #provision} mint leg for one resolved localpart. */
    private Mono<MintedToken> mintProvisioned(Jwt jwt, boolean matrix, String localpart) {
        // Defence in depth, mirroring admin-bff: a reserved handle should already
        // have been refused at registration, but the mint creates a REAL homeserver
        // localpart, so re-check at the provision point.
        if (ReservedNames.isReserved(localpart)) {
            return Mono.error(ApiException.badRequest(
                    "username '" + localpart + "' is reserved and cannot be provisioned"));
        }
        String owner = jwt.getSubject();
        Mono<MintedToken> mint = matrix
                ? broker.mintMatrix(owner, localpart)
                : broker.mintMastodon(owner, localpart);
        return mint.onErrorMap(LegacyPathParityController::asGatewayFailure);
    }

    /** Keep an error that already carries an HTTP status; map anything else to 502, which is
     *  what admin-bff's {@code onErrorResume(e -> ApiException.badGateway(...))} does. */
    private static Throwable asGatewayFailure(Throwable e) {
        if (e instanceof ApiException || e instanceof ResponseStatusException) {
            return e;
        }
        return ApiException.badGateway(String.valueOf(e));
    }

    // ── POST /bff/register/{google,discord} ───────────────────────────────────────────────

    /**
     * Invite-gated Google/email self-registration — admin-bff {@code AuthController#registerGoogle}
     * parity. The invite namespace is {@code google} ({@code AccountStore.isEmailInvited}), the
     * account is keyed {@code google:<email>}, and a fresh opaque {@code bff_} session is minted
     * (cookie + body token) exactly as user-bff's own {@code POST /bff/register} does.
     *
     * <p>{@code operationId} is kept as admin-bff's {@code authRegisterGoogle} so an
     * ng-openapi-gen client regenerated against THIS spec keeps the method name the existing
     * generated clients already carry.
     *
     * <p>403 when the address is not invited; 409 on a homeserver-localpart collision;
     * <b>409 when the account has already completed registration</b> (decision 57 — see the
     * class doc; the two 409 bodies differ); 502 when the internal hop to admin-bff fails. A
     * performed registration is recorded on admin-bff's usage table (decision 55), detached
     * from the response.
     */
    @Operation(summary = "Invite-gated Google/email registration: ensure the account and mint a "
            + "bff_ session. admin-bff AuthController parity. 403 when not invited; 409 on a "
            + "localpart collision; 409 for an already-complete account (decision 57: conflict "
            + "with the existing account, no restart of onboarding). Records a register usage "
            + "row on admin-bff (decision 55), fire-and-forget.",
            operationId = "authRegisterGoogle")
    @PostMapping("/register/google")
    public Mono<ResponseEntity<Map<String, Object>>> registerGoogle(
            @Valid @RequestBody RegisterEmailRequest body, ServerWebExchange exchange) {
        return register("google", body.email(), "email not invited by an admin", exchange);
    }

    /**
     * Invite-gated Discord self-registration — admin-bff {@code AuthController#registerDiscord}
     * parity. See {@link #registerGoogle}; the invite namespace is {@code discord}
     * ({@code AccountStore.isDiscordInvited}) and the account is keyed {@code discord:<username>}.
     */
    @Operation(summary = "Invite-gated Discord registration: ensure the account and mint a bff_ "
            + "session. admin-bff AuthController parity. 403 when not invited; 409 on a localpart "
            + "collision; 409 for an already-complete account (decision 57: conflict with the "
            + "existing account, no restart of onboarding). Records a register usage row on "
            + "admin-bff (decision 55), fire-and-forget.",
            operationId = "authRegisterDiscord")
    @PostMapping("/register/discord")
    public Mono<ResponseEntity<Map<String, Object>>> registerDiscord(
            @Valid @RequestBody RegisterDiscordRequest body, ServerWebExchange exchange) {
        return register("discord", body.username(), "discord username not invited by an admin",
                exchange);
    }

    /**
     * The shared registration leg, in admin-bff's order: invite gate, ensure-the-account (which
     * persists the collision-checked localpart on admin-bff's side), the already-complete gate
     * (409, decision 57 — standing exactly where admin-bff's
     * {@code .flatMap(store::restartOnboarding)} stands), the usage row (decision 55 — standing
     * exactly where admin-bff's {@code emitAndSession} fires {@code usage.record(...).subscribe()},
     * i.e. before the mint and detached from it), then mint.
     *
     * <p>{@code handle} is trimmed + lowercased here, as admin-bff's {@code str(...).toLowerCase()}
     * does, so the allowlist lookup and the account key agree with the rows admin-bff writes.
     * {@link Locale#ROOT} is explicit: a Turkish default locale folds {@code I} to a dotless
     * {@code ı} and would key a DIFFERENT account than admin-bff's JVM.
     */
    private Mono<ResponseEntity<Map<String, Object>>> register(
            String provider, String rawHandle, String notInvitedMessage, ServerWebExchange exchange) {
        String handle = rawHandle == null ? "" : rawHandle.trim().toLowerCase(Locale.ROOT);
        return adminBff.allowlistCheck(provider, handle)
                .onErrorMap(LegacyPathParityController::asInternalHopFailure)
                .flatMap(invited -> Boolean.TRUE.equals(invited)
                        ? adminBff.ensureAccount(provider, handle)
                                .onErrorMap(LegacyPathParityController::asInternalHopFailure)
                        : Mono.error(ApiException.forbidden(notInvitedMessage)))
                .flatMap(account -> sessionForNewAccount(provider, handle, account, exchange));
    }

    /** The {@link #register} leg after ensure-the-account: the already-complete gate, the
     *  usage row, then the session mint. */
    private Mono<ResponseEntity<Map<String, Object>>> sessionForNewAccount(
            String provider, String handle, AdminBffInternalClient.AccountView account,
            ServerWebExchange exchange) {
        if (account.registrationComplete()) {
            // Decision 57: a re-registration of an already-complete account is a
            // CONFLICT with that account. No restart, no session, no usage row.
            return Mono.<ResponseEntity<Map<String, Object>>>error(
                    ApiException.conflict(ALREADY_REGISTERED_CONFLICT));
        }
        recordRegistration(provider, handle, account);
        return adminBff.createSession(account.id())
                .onErrorMap(LegacyPathParityController::asInternalHopFailure)
                .map(session -> emitAndSession(exchange, account, session));
    }

    /**
     * Decision 55: the registration usage row, over admin-bff's {@code POST /bff/internal/usage}
     * — the same {@code (handle, account.roles(), "register")} triple admin-bff's own
     * {@code emitAndSession} records, subscribed DETACHED from the response exactly as its
     * {@code usage.record(...).subscribe()} is. A failure is logged (provider + the error, never
     * the handle, which is an email address) and never reaches the caller: the account exists
     * and the session is minted regardless. The two-consumer {@code subscribe} matters — a bare
     * {@code subscribe()} would route the error to Reactor's {@code onErrorDropped} hook, which
     * logs at ERROR with a stack trace on every admin-bff hiccup.
     *
     * <p>{@link Mono#defer} matters too: this method runs inside the registration chain's
     * {@code flatMap} lambda, so an exception thrown while the client BUILDS its Mono (e.g. a
     * {@code NullPointerException} from {@code List.copyOf} on a roles list carrying a null
     * element) would otherwise escape into the response chain and turn a performed
     * registration into a 500. Deferred, that throw becomes an error signal of the detached
     * subscription and takes the same WARN path. Both properties, and that a usage call that
     * never answers does not delay the response, are pinned in
     * {@code LegacyPathParityRegisterTest}.
     */
    private void recordRegistration(String provider, String handle,
                                    AdminBffInternalClient.AccountView account) {
        Mono.defer(() -> adminBff.recordUsage(handle, account.roles(), USAGE_ACTION_REGISTER))
                .subscribe(ignored -> { },
                        e -> log.warn("[register/{}] usage row not recorded on admin-bff "
                                + "(decision 55 leg is fire-and-forget; registration unaffected): {}",
                                provider, String.valueOf(e)));
    }

    /**
     * admin-bff {@code emitAndSession} parity for the two register legs: mint the opaque
     * {@code bff_} cookie (when {@code app.session.cookie.enabled}) AND keep the token in the
     * body, which is the shape {@link SsoAuthController#register} already emits and the shape
     * hugmesh-generator's {@code tests/qemu/seed-accounts.sh} reads ({@code .token}).
     * {@code registrationComplete} is necessarily {@code false} here — a {@code true} account
     * was refused with 409 above (decision 57) — which is the same value admin-bff emits after
     * its {@code restartOnboarding}.
     */
    private ResponseEntity<Map<String, Object>> emitAndSession(
            ServerWebExchange exchange, AdminBffInternalClient.AccountView account,
            AdminBffInternalClient.SessionView session) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("token", session.token());
        body.put("id", account.id());
        body.put("provider", account.provider());
        body.put("registrationComplete", account.registrationComplete());
        body.put("roles", account.roles());
        ResponseEntity.BodyBuilder builder = ResponseEntity.ok();
        if (cookies.enabled()) {
            builder.header("Set-Cookie",
                    cookies.mint(exchange.getRequest(), session.token()).toString());
        }
        return builder.body(body);
    }

    /**
     * Map a failure of the {@code /bff/internal/**} hop onto the status the CALLER should see.
     * A {@code 409} is admin-bff's localpart-collision refusal and is re-raised as a {@code 409}
     * (status parity with admin-bff's {@code ApiException.conflict}) — distinct in its BODY from
     * the already-complete 409 of decision 57 ({@link #ALREADY_REGISTERED_CONFLICT}), which is
     * raised by this class, not by the hop; anything else that is not
     * already status-carrying becomes a {@code 502}, the same wrap
     * {@link #asGatewayFailure} applies on the provision legs. Without this an internal
     * {@link WebClientResponseException} is not a {@link ResponseStatusException} and would
     * surface as an opaque 500.
     */
    private static Throwable asInternalHopFailure(Throwable e) {
        if (e instanceof WebClientResponseException.Conflict) {
            return ApiException.conflict("registration conflicts with an existing account "
                    + "(the homeserver localpart for this handle is already taken)");
        }
        return asGatewayFailure(e);
    }

    // ── helpers ───────────────────────────────────────────────────────────────────────────

    /**
     * The caller's OWN account id, via {@link CanonicalIdentityResolver#ownAccountId(Jwt)} —
     * verbatim for a {@code bff_}-session synthetic principal (whose {@code sub} IS
     * {@code provider:handle}), else {@code casdoor:<subject>}. 401 when the principal is
     * absent or carries no usable identity claim; NEVER a cross-namespace guess.
     */
    private static Mono<String> ownAccountId(Jwt jwt) {
        String id = jwt == null ? null : CanonicalIdentityResolver.ownAccountId(jwt);
        return id == null
                ? Mono.error(ApiException.unauthorized("login required"))
                : Mono.just(id);
    }

    /**
     * admin-bff's {@code if (!me.registrationComplete()) 403 "complete registration first"}
     * gate, resolved over the internal surface. It is belt-and-braces on the {@code bff_}
     * carrier — {@code BffSessionAuthenticationWebFilter} strips every role but the
     * {@code ROLE_USER} floor from an incomplete registration, so {@code @PreAuthorize} has
     * already 403'd — but it is the ONLY thing that enforces the gate for a raw Casdoor JWT
     * carrier, whose token says nothing about registration state. A 404 from the internal read
     * is mapped to 401, matching admin-bff's {@code me()}.
     */
    private Mono<AdminBffInternalClient.AccountView> requireCompleteAccount(Jwt jwt) {
        return ownAccountId(jwt)
                .flatMap(id -> adminBff.getAccount(id)
                        .onErrorResume(WebClientResponseException.NotFound.class, e -> Mono.empty())
                        .switchIfEmpty(Mono.error(ApiException.unauthorized("login required"))))
                .flatMap(account -> account.registrationComplete()
                        ? Mono.just(account)
                        : Mono.error(ApiException.forbidden("complete registration first")));
    }
}
