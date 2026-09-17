package net.hugmesh.userbff.auth;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Mono;
import net.hugmesh.authcore.reserved.ReservedNames;
import net.hugmesh.commons.web.ApiException;
import net.hugmesh.userbff.hsproxy.HsTokenCustody;
import net.hugmesh.userbff.hsproxy.MintedToken;
import net.hugmesh.userbff.hsproxy.ServiceTokenBroker;

import java.util.List;
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
 * <h2>The four DELIBERATE divergences, and why each one is not a regression</h2>
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
 *       account-takeover vector it was created to delete. This class uses the resolver — the
 *       caller's OWN {@code casdoor:<subject>} account, claim-first off a {@code bff_}-session
 *       synthetic principal. <b>On the {@code bff_} carrier the two are identical</b> (the
 *       synthetic {@code sub} IS the account id {@code provider:handle}), and that is the only
 *       carrier the live callers use — login-ui and admin-ui both ride the httpOnly
 *       {@code bff_} cookie. Reproducing admin-bff's JWT branch would re-open a closed
 *       takeover class.</li>
 *   <li><b>No self-heal of a blank persisted localpart.</b> admin-bff's {@code provision} calls
 *       {@code AccountLocalpartService.resolveAndPersist} when {@code account.localpart} is
 *       blank and then mints; user-bff owns no account table, so {@link
 *       CanonicalIdentityResolver} FAILS CLOSED instead — 409 on a raw Casdoor JWT carrier,
 *       401 on a {@code bff_} carrier (the resolver probes {@code casdoor:<sub>} on the
 *       claim-absent branch even when the {@code sub} is already a full account id; both are
 *       pinned in {@code LegacyPathParityControllerTest}). Unreachable on the cluster lane in
 *       practice: {@code POST /bff/login} routes here and its {@code ensureAccount} hop makes
 *       admin-bff persist the localpart on EVERY sign-in, so a caller holding a session holds
 *       a localpart.</li>
 * </ol>
 *
 * <h2>The two paths that are NOT here</h2>
 *
 * <p>{@code POST /bff/register/google} and {@code POST /bff/register/discord} could not be
 * built faithfully from user-bff, which owns no account table: admin-bff's handlers also call
 * {@code AccountStore.restartOnboarding} (reset {@code registrationComplete} to false on a
 * RE-registration) and {@code UsageService.record(handle, roles, "register")}, and neither has
 * an endpoint on admin-bff's {@code /bff/internal/**} surface. A handler without them would
 * silently leave a re-registering account marked complete — a divergence a caller can see.
 * The exact internal-API additions needed are written as numbered boxes on
 * hugmesh/hugmesh-admin-bff-api#2.
 *
 * @see SsoAuthController the OIDC-era login/register/session surface this sits beside
 * @see CanonicalIdentityResolver the single homeserver-identity policy
 */
@Tag(name = "Legacy path parity", description =
        "admin-bff AuthController parity for the cluster-routed legacy user paths "
                + "(/bff/me/namespaces, /bff/provision/matrix, /bff/provision/mastodon). "
                + "Decision 25 on hugmesh-generator#347: parity first, then retire.")
@RestController
@RequestMapping("/bff")
public class LegacyPathParityController {

    /** The exact body the generator's mock-bff already answers {@code /bff/provision/*} with. */
    private static final Map<String, Object> OK = Map.of("ok", true);

    private final AdminBffInternalClient adminBff;
    private final CanonicalIdentityResolver identity;
    private final HsTokenCustody custody;
    private final ServiceTokenBroker broker;
    /** {@code app.hs-token.enabled} — the same gate the D6 proxy controllers read. */
    private final boolean hsTokenEnabled;

    public LegacyPathParityController(AdminBffInternalClient adminBff,
                                      CanonicalIdentityResolver identity,
                                      HsTokenCustody custody,
                                      ServiceTokenBroker broker,
                                      @Value("${app.hs-token.enabled:false}") boolean hsTokenEnabled) {
        this.adminBff = adminBff;
        this.identity = identity;
        this.custody = custody;
        this.broker = broker;
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
                .flatMap(localpart -> {
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
                })
                .thenReturn(OK);
    }

    /** Keep an error that already carries an HTTP status; map anything else to 502, which is
     *  what admin-bff's {@code onErrorResume(e -> ApiException.badGateway(...))} does. */
    private static Throwable asGatewayFailure(Throwable e) {
        if (e instanceof ApiException || e instanceof ResponseStatusException) {
            return e;
        }
        return ApiException.badGateway(String.valueOf(e));
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
