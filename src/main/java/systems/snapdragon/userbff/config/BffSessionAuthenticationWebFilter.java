package systems.snapdragon.userbff.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClientRequestException;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import systems.snapdragon.commons.security.DomainRegistry;
import systems.snapdragon.userbff.auth.AdminBffInternalClient;
import systems.snapdragon.userbff.auth.AdminBffInternalClient.AccountView;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * SERVICE-LOCAL BFF SESSION AUTHENTICATION (HTTP-introspection variant) — bridges an
 * opaque {@code bff_} session token into a REAL Spring Security {@link Authentication}
 * so this service's OWN declarative {@code hasAnyRole()}/{@code hasRole()}/
 * {@code .authenticated()} gates ({@link SecurityConfig}) can see it, exactly like
 * {@code BffCookieAuthenticationWebFilter} does for admin-bff-api — except THIS service
 * has no local database access to the accounts/bff_session tables (mutual db-denial
 * NetworkPolicy with admin-bff, see {@link AdminBffInternalClient}'s own doc comment),
 * so the session must be resolved over HTTP instead of a local repository lookup.
 *
 * <h3>Why this exists</h3>
 * The gateway's own {@code BffSessionAuthFilter} (snapdragon-gateway) authenticates a
 * bff_ session AT THE GATEWAY, for the gateway's OWN route-access decision — but that
 * authentication is local to the gateway's request-processing context; it never reaches
 * a downstream service's OWN {@code oauth2ResourceServer().jwt(...)} config, which is
 * (correctly) inert to a non-JWT bff_ token. Until this filter, NOTHING authenticated a
 * bff_-cookie-only request against user-bff's OWN {@code hasAnyRole()}/
 * {@code .authenticated()} gate: the ENTIRE {@code /bff/user/**} surface (profile,
 * notifications, Matrix/Mastodon proxying, blocking, character customization,
 * preferences, connected-clients, sessions, self-silence, account status) plus
 * {@code /bff/me} was architecturally unreachable via native login, regardless of what
 * the gateway itself decided.
 *
 * <h3>Resolution — HTTP, not a local {@code AccountStore}</h3>
 * Delegates to the ALREADY-EXISTING {@link AdminBffInternalClient#getAccountBySession},
 * which introspects the token against admin-bff's {@code GET
 * /bff/internal/session/introspect} (resolving token → account id) and then fetches the
 * full {@link AccountView} — the SAME two-hop pattern the gateway's own filter performs
 * at the gateway layer. This is a deliberate, accepted tradeoff: the gateway's own
 * route-access decision does not propagate downstream, so protecting THIS service's own
 * gates needs its own HTTP round-trip to admin-bff (an unavoidable extra hop without a
 * bigger cross-service redesign).
 *
 * <h3>Authority mapping</h3>
 * Mirrors {@code BffCookieAuthenticationWebFilter.buildAuthorities} / the gateway's
 * {@code BffSessionAuthFilter.buildAuthorities}: {@code ROLE_USER} floor always; if
 * {@code !registrationComplete}, ONLY the floor (no roles, no {@code MFA_SATISFIED});
 * otherwise each role maps to {@code ROLE_<UPPER>} (deduplicated against the floor) and
 * {@link #MFA_SATISFIED} is appended when the session's MFA challenge is satisfied.
 *
 * <p><b>{@code MFA_SATISFIED} is now plumbed with full fidelity.</b> The earlier version
 * of this filter deliberately omitted it because {@link
 * AdminBffInternalClient#getAccountBySession} discarded everything from the introspect
 * response except the account id. This filter now resolves via {@link
 * AdminBffInternalClient#resolveSession}, which carries the introspect body's
 * {@code status} + {@code mfaSatisfied} through the (unchanged, two-hop) resolution
 * alongside the account view, so {@code MFA_SATISFIED} is granted with the same fidelity
 * the gateway's own filter grants it. No {@code hasAuthority("MFA_SATISFIED")} gate exists
 * in this service's controllers TODAY, but granting it now means a future MFA-gated
 * endpoint here cannot silently ship ungated the way it would have before.
 *
 * <h3>Suspended/banned accounts — explicit deny, mirroring the gateway</h3>
 * admin-bff's introspect body may report {@code status: "suspended"|"banned"} on a
 * still-live session (the suspension check is live, not cached). Exactly like the
 * gateway's own {@code BffSessionAuthFilter} and mod-bff-api's filter, this is an
 * explicit {@code 403} + {@code X-Bff-Denied} — the exchange is completed directly and
 * {@code chain.filter(exchange)} is NEVER called on that branch — rather than silently
 * degrading to "unauthenticated" (which would still 401, but would blur a deliberate ban
 * into an ordinary invalid/absent token). Defence-in-depth: the gateway already denies a
 * banned session before proxying here in production, but this service's own gate should
 * not depend on that for correctness.
 *
 * <h3>Fail-closed posture</h3>
 * <ul>
 *   <li>Unknown/expired session (admin-bff introspect 401, which {@link
 *       AdminBffInternalClient#getAccountBySession} maps to a {@link
 *       ResponseStatusException} with {@link HttpStatus#UNAUTHORIZED}) → PASS THROUGH
 *       unauthenticated; the downstream {@code .authenticated()} rule produces a clean
 *       401 for protected paths, {@code permitAll()} paths still succeed. This is the
 *       ONLY error case that passes through.</li>
 *   <li>Every OTHER introspection failure — a raw {@link WebClientResponseException}
 *       (5xx or an unexpected 4xx other than 401), a {@link WebClientRequestException}
 *       (connection refused / DNS failure), or a timeout (see {@link
 *       #DEFAULT_INTROSPECTION_TIMEOUT_MS}, since {@code getAccountBySession} itself
 *       sets none) —
 *       is FAIL-CLOSED: {@code 503 Service Unavailable}, downstream is NEVER reached.
 *       Mirrors the gateway's own {@code BffSessionAuthFilter.onErrorResume} precedent
 *       exactly: a bff_ token that cannot be validated is never silently treated as
 *       either authenticated OR anonymous-but-let-through — a transient admin-bff
 *       outage must not quietly demote every native-login caller to "logged out".</li>
 *   <li>The bridging capability being ABSENT altogether — no {@link
 *       AdminBffInternalClient} bean in the context (e.g. a {@code @WebFluxTest} slice
 *       that never wires it) OR the bean present but {@link
 *       AdminBffInternalClient#enabled()} is {@code false} (this deployment's whole
 *       login surface ships dark behind {@code app.bff.oidc.enabled=false}, so the
 *       client is the documented fail-closed STUB whose every call errors with an
 *       {@link IllegalStateException}) — is treated as PASS-THROUGH, not 503. This is a
 *       deliberate departure from the "everything-but-401-is-503" rule above: those two
 *       conditions are PERMANENT per-deployment states, not transient faults, so
 *       returning 503 forever would be a worse outcome than the caller simply falling
 *       through to the existing {@code .authenticated()} 401 (identical security
 *       posture either way — no authority is ever granted on either path). The {@code
 *       enabled()} check happens BEFORE calling {@code getAccountBySession}, so the
 *       stub's {@link IllegalStateException} is never actually thrown here.</li>
 * </ul>
 *
 * <h3>Ordering</h3>
 * Runs at {@code HIGHEST_PRECEDENCE + 10}, the same convention as auth-core's {@code
 * BffCookieAuthenticationWebFilter}. user-bff has no {@code SessionCookieWebFilter} of
 * its own registered ({@code AuthCoreImport} does not import it — confirmed via {@code
 * grep -rn SessionCookieWebFilter src/main}, the only reference is a plain string
 * constant in {@code SsoAuthController}), so this filter does its OWN dual token
 * extraction (header, then cookie) rather than relying on prior normalisation, mirroring
 * the gateway's own {@code BffSessionAuthFilter.extractToken} exactly. Still needs to
 * run before Spring Security's {@code AUTHENTICATION} filter slot / the JWT {@code
 * BearerTokenAuthenticationWebFilter} so a populated {@code SecurityContext} here
 * short-circuits the (inert-anyway) JWT resource-server attempt.
 *
 * <h3>Non-interference with JWT auth</h3>
 * Skips immediately (no admin-bff call) when the {@code Authorization} header/cookie
 * carries no {@code bff_}-prefixed token — a real Casdoor JWT request is completely
 * untouched by this filter.
 *
 * <h3>Exactly-once {@code chain.filter(exchange)} invariant</h3>
 * A prior implementation of this same bridge (auth-core's {@code
 * BffCookieAuthenticationWebFilter}) shipped a bug where {@code
 * resolved.flatMap(auth -> chain.filter(exchange)...).switchIfEmpty(chain.filter
 * (exchange))} called {@code chain.filter(exchange)} TWICE on every successful auth,
 * because {@code chain.filter()} returns {@code Mono<Void>}, which never emits {@code
 * onNext} even on successful completion — so {@code switchIfEmpty} always treated a
 * successful completion as "empty" too. This class avoids that shape entirely: {@link
 * #resolve} first settles to a single {@code Mono<Optional<Authentication>>} (mapping
 * the ONE recoverable error — a mapped 401 — to {@code Optional.empty()}, and
 * re-throwing every other error as an internal {@link IntrospectionFailure} marker
 * BEFORE any {@code flatMap} that could call {@code chain.filter}), and {@link #filter}
 * then branches on that {@code Optional} from EXACTLY ONE {@code flatMap} arm. The
 * fail-closed {@link IntrospectionFailure} catch is deliberately scoped to wrap only
 * {@link #resolve}'s own error channel (composed BEFORE the {@code flatMap} that invokes
 * {@code chain.filter}), not the whole downstream pipeline — so a genuine exception
 * raised later, inside the protected handler itself, is never mistaken for an
 * introspection failure and swallowed into a spurious 503.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 10)
public class BffSessionAuthenticationWebFilter implements WebFilter {

    private static final Logger log = LoggerFactory.getLogger(BffSessionAuthenticationWebFilter.class);

    /** Cookie name — matches auth-core's {@code SessionCookieService} / the gateway's
     *  {@code BffSessionAuthFilter.SESSION_COOKIE} constant. */
    static final String SESSION_COOKIE = "bff_session";

    /** Token prefix that uniquely identifies opaque BFF session tokens. */
    static final String BFF_PREFIX = "bff_";

    /** Authority granted when the session's MFA challenge has been satisfied. Matches the
     *  gateway's own {@code BffSessionAuthFilter.MFA_SATISFIED} and auth-core /
     *  mod-bff-api's {@code BffCookieAuthenticationWebFilter.MFA_SATISFIED} constant. */
    static final String MFA_SATISFIED = "MFA_SATISFIED";

    /** Reactor context key holding the RAW {@code bff_} session token of an authenticated
     *  native-login request. Populated by this filter (AUTHENTICATE branch) so the outbound
     *  bearer-forwarding filters can swap it for a real custody JWT — the SecurityContext's
     *  synthetic Jwt principal carries only a non-forwardable marker, never a credential.
     *  Public so {@code FederationWebClientConfig}/{@code MediaWebClientConfig} read the same
     *  key without a second, driftable literal. */
    public static final String BFF_SESSION_TOKEN_CONTEXT_KEY = "snapdragon.userbff.bff-session-token";

    /** Response header naming why a request was explicitly denied by this filter
     *  (suspended/banned branch only) — mirrors the gateway's {@code X-BFF-Denied}. */
    private static final String DENIED_HEADER = "X-Bff-Denied";

    /** Default bounded wait on the admin-bff introspection round-trip. {@code
     *  AdminBffInternalClient.resolveSession} sets no timeout of its own (unlike
     *  the gateway's equivalent call), so an unresponsive-but-still-connected admin-bff
     *  would otherwise hang this request indefinitely instead of failing closed. */
    static final long DEFAULT_INTROSPECTION_TIMEOUT_MS = 3000L;

    /** Internal marker wrapping any {@link #resolve} failure OTHER than a mapped 401,
     *  so the fail-closed 503 branch in {@link #filter} can be scoped to introspection
     *  errors ONLY — see the exactly-once invariant discussion above. Never escapes this
     *  class. */
    private static final class IntrospectionFailure extends RuntimeException {
        IntrospectionFailure(Throwable cause) {
            super(cause);
        }
    }

    private final ObjectProvider<AdminBffInternalClient> adminBffClient;

    /** Bounded wait applied to every introspection call. Overridable via {@code
     *  app.bff-session-auth.introspection-timeout-ms} (default {@link
     *  #DEFAULT_INTROSPECTION_TIMEOUT_MS}) for tests/tuning. A SINGLE constructor (no
     *  overload) so Spring's implicit-constructor autowiring applies unambiguously. */
    private final Duration introspectionTimeout;

    /** Issuer-&gt;domain registry — consulted ONLY to populate the synthetic {@link Jwt}
     *  principal's {@code iss} claim (see {@link #syntheticJwt}); never used to validate
     *  anything (this filter never decodes a real token). Always present: {@code
     *  DomainRegistry} is an unconditional {@code @Component} (via {@code
     *  CommonsSecurityConfig}), and every {@code @WebFluxTest} slice in this repo already
     *  {@code @Import}s {@link SecurityConfig} (which pulls it in) — confirmed by grep
     *  across the existing slice-test suite before adding this as a required (not {@code
     *  ObjectProvider}) dependency, matching {@link SecurityConfig}'s own convention. */
    private final DomainRegistry domainRegistry;

    public BffSessionAuthenticationWebFilter(
            ObjectProvider<AdminBffInternalClient> adminBffClient,
            @Value("${app.bff-session-auth.introspection-timeout-ms:" + DEFAULT_INTROSPECTION_TIMEOUT_MS + "}")
            long introspectionTimeoutMs,
            DomainRegistry domainRegistry) {
        this.adminBffClient = adminBffClient;
        this.introspectionTimeout = Duration.ofMillis(introspectionTimeoutMs);
        this.domainRegistry = domainRegistry;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String token = extractToken(exchange);
        if (token == null) {
            // No bff_ token present — leave the JWT path completely undisturbed.
            return chain.filter(exchange);
        }

        AdminBffInternalClient client = adminBffClient.getIfAvailable();
        if (client == null || !client.enabled()) {
            // No bridging capability in this deployment/test-slice — a PERMANENT
            // condition, not a transient fault (see class doc "Fail-closed posture").
            // Pass through unauthenticated; .authenticated() produces the clean 401.
            return chain.filter(exchange);
        }

        return resolve(client, token)
                .flatMap(decision -> apply(decision, token, exchange, chain))
                .onErrorResume(IntrospectionFailure.class, ex -> failClosed(exchange, ex));
    }

    private Mono<Void> apply(Decision d, String token, ServerWebExchange exchange, WebFilterChain chain) {
        return switch (d.kind()) {
            // Stash the RAW bff_ token in the Reactor context alongside the Authentication.
            // The SecurityContext principal is a SYNTHETIC, non-forwardable Jwt (its token
            // value is a marker, not a credential), so the outbound bearer-forwarding filters
            // ({@code FederationWebClientConfig}/{@code MediaWebClientConfig}) read this key to
            // swap the session for a real custody JWT at forward time (see that filter). The
            // raw token lives ONLY in the request-scoped Reactor context, never in the
            // principal / a header / a log line.
            case AUTHENTICATE -> chain.filter(exchange)
                    .contextWrite(ctx -> ctx.put(BFF_SESSION_TOKEN_CONTEXT_KEY, token))
                    .contextWrite(ReactiveSecurityContextHolder.withAuthentication(d.authentication()));
            case PASS_THROUGH -> chain.filter(exchange);
            case FORBIDDEN -> reject(exchange, HttpStatus.FORBIDDEN, "account-" + d.reason());
        };
    }

    /** The outcome of a bff_ token lookup, branched on exactly once by {@link #apply}.
     *  Package-private so a unit test can assert on decisions directly. */
    enum Kind { AUTHENTICATE, PASS_THROUGH, FORBIDDEN }

    record Decision(Kind kind, Authentication authentication, String reason) {
        static Decision authenticate(Authentication a) { return new Decision(Kind.AUTHENTICATE, a, null); }
        static Decision passThrough() { return new Decision(Kind.PASS_THROUGH, null, null); }
        static Decision forbidden(String reason) { return new Decision(Kind.FORBIDDEN, null, reason); }
    }

    /**
     * Resolves the token to a {@link Decision}: AUTHENTICATE (synthetic-Jwt principal) for
     * a live account, FORBIDDEN for a suspended/banned session (an explicit 403, mirroring
     * the gateway's own {@code BffSessionAuthFilter} and mod-bff-api's filter — a deliberate
     * ban decision must not blur into an ordinary "unauthenticated" 401), PASS_THROUGH for
     * an unknown/expired session (mapped 401), or an error signal (wrapped as {@link
     * IntrospectionFailure}) for anything else. Composed entirely BEFORE {@link #filter}'s
     * {@code flatMap} that calls {@code chain.filter} — see the exactly-once invariant
     * discussion in the class doc.
     */
    private Mono<Decision> resolve(AdminBffInternalClient client, String token) {
        return client.resolveSession(token)
                .timeout(introspectionTimeout)
                // resolveSession() is documented to always emit exactly one SessionResolution
                // or error — but WebClient.bodyToMono() completes EMPTY (no item, no error)
                // for a 2xx response with no/blank body, which would otherwise fall straight
                // through map/onErrorResume/onErrorMap untouched (none of them run on an
                // empty completion) and leave filter()'s flatMap never invoked at all —
                // silently neither authenticating, passing through, NOR failing closed.
                // Treat that as a resolution failure too, so it lands in the same fail-closed
                // 503 branch as every other unexpected admin-bff response shape.
                .switchIfEmpty(Mono.error(new IllegalStateException(
                        "admin-bff introspection returned no body for a 2xx response")))
                .map(this::decide)
                .onErrorResume(ResponseStatusException.class, ex -> {
                    if (ex.getStatusCode().value() == HttpStatus.UNAUTHORIZED.value()) {
                        // Unknown/expired session — pass through unauthenticated.
                        return Mono.just(Decision.passThrough());
                    }
                    // Not the mapped-401 case (shouldn't normally happen — see
                    // resolveSession's own onErrorMap — but don't silently swallow
                    // an unexpected status either): fail closed like everything else.
                    return Mono.error(ex);
                })
                .onErrorMap(ex -> !(ex instanceof IntrospectionFailure), IntrospectionFailure::new);
    }

    /** Package-private so a unit test can exercise the status/authority decision directly. */
    Decision decide(AdminBffInternalClient.SessionResolution resolution) {
        String status = resolution.status();
        if ("suspended".equalsIgnoreCase(status) || "banned".equalsIgnoreCase(status)) {
            log.warn("[bff-session] denied — account status={} id={}", status, resolution.account().id());
            return Decision.forbidden(status.toLowerCase(Locale.ROOT));
        }
        return Decision.authenticate(authenticationFor(resolution.account(), resolution.mfaSatisfied()));
    }

    private static Mono<Void> reject(ServerWebExchange exchange, HttpStatus status, String reason) {
        exchange.getResponse().setStatusCode(status);
        exchange.getResponse().getHeaders().add(DENIED_HEADER, reason);
        return exchange.getResponse().setComplete();
    }

    private static Mono<Void> failClosed(ServerWebExchange exchange, IntrospectionFailure ex) {
        Throwable cause = ex.getCause() != null ? ex.getCause() : ex;
        log.error("[bff-session] admin-bff introspection failed ({}: {}) — returning 503",
                cause.getClass().getSimpleName(), cause.getMessage());
        exchange.getResponse().setStatusCode(HttpStatus.SERVICE_UNAVAILABLE);
        exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);
        byte[] body = "{\"error\":\"session_backend_unavailable\"}".getBytes(StandardCharsets.UTF_8);
        var buffer = exchange.getResponse().bufferFactory().wrap(body);
        return exchange.getResponse().writeWith(Mono.just(buffer));
    }

    // ── token extraction ──────────────────────────────────────────────────────

    /**
     * Extracts the {@code bff_} token from the exchange. Checks the {@code
     * Authorization: Bearer} header first, then the {@code bff_session} cookie —
     * identical priority order (and identical logic) to the gateway's own {@code
     * BffSessionAuthFilter.extractToken}: if the header carries SOME OTHER bearer token
     * (e.g. a Casdoor JWT), extraction stops there and returns {@code null} — it does
     * NOT fall through to the cookie (a request already carrying a real JWT should never
     * be reinterpreted via a stale cookie). The header branch checks the {@code bff_}
     * prefix explicitly because a JWT can arrive in the SAME header; the cookie branch
     * does not re-check the prefix (matching the gateway exactly) because a {@code
     * bff_session} cookie's value is, by construction, always a raw {@code bff_} token —
     * there is no other value that could ever land in a cookie under this specific name.
     */
    static String extractToken(ServerWebExchange exchange) {
        String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authHeader != null) {
            String trimmed = authHeader.trim();
            if (trimmed.regionMatches(true, 0, "Bearer ", 0, 7)) {
                String candidate = trimmed.substring(7).trim();
                return candidate.startsWith(BFF_PREFIX) ? candidate : null;
            }
        }

        var cookies = exchange.getRequest().getCookies();
        var cookieList = cookies.get(SESSION_COOKIE);
        if (cookieList != null && !cookieList.isEmpty()) {
            String value = cookieList.get(0).getValue();
            if (value != null && !value.isBlank()) {
                return value;
            }
        }

        return null;
    }

    // ── authority mapping ─────────────────────────────────────────────────────

    /**
     * Non-secret, non-decodable token-value MARKER for {@link #syntheticJwt} — never the
     * real {@code bff_} session token (a live bearer credential that must never be
     * echoed into a {@link Jwt#getTokenValue()} accessor some framework/log line could
     * surface) and deliberately NOT shaped like a real JWT (no {@code .} delimiters), so
     * it can never be mistaken for, or misused as, an independently-verifiable
     * credential if it ever appears in a log line.
     *
     * <p><b>Public</b> (not {@code private}) so outbound token-forwarding filters —
     * {@code FederationWebClientConfig.bearerTokenForwardingFilter()} (reused by {@code
     * MediaWebClientConfig}) — can recognize and skip re-forwarding this marker as a
     * purported bearer credential to federation-api / the homeserver proxies. Before this
     * filter existed, a {@code bff_}-session {@link Authentication} was a plain {@code
     * UsernamePasswordAuthenticationToken}, which that forwarding filter's {@code
     * instanceof JwtAuthenticationToken} check never matched, so native-login callers sent
     * no {@code Authorization} header on those calls. Wrapping the principal in a {@link
     * JwtAuthenticationToken} here (see {@link #authenticationFor}) made that filter start
     * matching for the first time — an unreviewed side effect that would otherwise leak
     * this marker (which embeds the caller's real account id in cleartext) downstream as a
     * bearer credential. The forwarding filter's own marker check restores the pre-fix "no
     * header sent" behavior for this specific, non-forwardable case while leaving a real
     * Casdoor JWT's forwarding completely unaffected.
     */
    public static final String SYNTHETIC_TOKEN_MARKER = "bff-session-principal:";

    /**
     * Builds the {@link Authentication} for a resolved {@code bff_} session — a {@link
     * JwtAuthenticationToken} wrapping a SYNTHETIC (never cryptographically signed,
     * never decoded from client input) {@link Jwt}, so every one of this service's 16
     * {@code @AuthenticationPrincipal Jwt jwt} controllers resolves a REAL, non-null
     * {@link Jwt} — not the plain-{@link String}-principal shape this method returned
     * before this fix, which silently resolved to a {@code null} {@code jwt} parameter
     * (Spring's {@code AuthenticationPrincipalArgumentResolver} defaults {@code
     * errorOnInvalidType()} to {@code false}) and NPE'd every one of those handlers
     * (live-reproduced: 500, "Cannot invoke Jwt.getSubject() because jwt is null").
     *
     * <p>This is placed DIRECTLY into the {@code SecurityContext} server-side and is
     * NEVER decoded/re-verified from client input (unlike a real resource-server JWT),
     * so it needs no signature — see {@link #syntheticJwt}.
     */
    private Authentication authenticationFor(AccountView view, boolean mfaSatisfied) {
        return new JwtAuthenticationToken(syntheticJwt(view), buildAuthorities(view, mfaSatisfied));
    }

    /**
     * Builds the Jwt-SHAPED principal for {@link #authenticationFor}. Populates every
     * claim this service's controllers are known to read off a real Casdoor {@link Jwt}:
     *
     * <ul>
     *   <li>{@code sub} = {@link AccountView#id()} — the SAME value the pre-fix plain
     *       {@link String} principal carried, so {@code jwt.getSubject()} (the owner
     *       key every controller scopes reads/writes by) is unchanged.</li>
     *   <li>{@code roles} = {@link AccountView#roles()} (gated on {@code
     *       registrationComplete}, EXACTLY mirroring {@link #buildAuthorities}) so
     *       {@code Roles.fromJwt}/{@code Roles.isSuperadmin(Jwt)}/{@code Roles.has(Jwt,
     *       ...)} — the raw-{@code Jwt}-reading overloads, distinct from the
     *       already-correct authorities-collection overloads this filter already fed —
     *       agree with the authorities on this SAME {@link Authentication}.</li>
     *   <li>{@code email} (provider {@code "google"}) or {@code preferred_username}
     *       (every other provider) = {@link AccountView#handle()} — best-effort so the
     *       {@code preferred_username}-with-{@code sub}-fallback pattern used by {@code
     *       ProfileController.usernameOf}/{@code ConnectedClientsController.localpart}/
     *       {@code MatrixProxyController.localpart}/{@code
     *       MastodonProxyController.localpart}/{@code SelfSilenceController.localpart}
     *       resolves a real handle instead of falling back to the "{@code
     *       provider:handle}" composite {@code sub} string (which is not a valid
     *       homeserver localpart). For {@code "google"}/{@code "discord"} accounts this
     *       ALSO makes {@code SessionsService.accountIdFromJwt} reconstruct the EXACT
     *       account id admin-bff stored, so {@code SessionsController} (one of the 16)
     *       works correctly end-to-end for those two provider types.
     *       <p><b>Known residual gap (pre-existing, NOT introduced or fixed here):</b>
     *       {@code SessionsService.accountIdFromJwt} only ever reconstructs a {@code
     *       "google:"} or {@code "discord:"} prefixed id — it has NO branch for {@code
     *       "casdoor"} (the native-login provider {@code AccountView} accounts mostly
     *       carry today, per admin-bff's {@code InternalAccountController#ensureAccount}
     *       "#112 SSO subject extraction" doc). A REAL Casdoor JWT for a casdoor-provider
     *       account already hits this exact mismatch today (independent of this filter
     *       or either Bug-2 fix option), so {@code SessionsController} already returns
     *       an empty list / 404s any revoke for native-login accounts via ANY carrier;
     *       this fix does not regress that further, but does not fix it either — flagged
     *       here rather than silently worked around, since a real fix belongs in {@code
     *       SessionsService}, out of this change's scope.</li>
     *   <li>{@code localpart} = {@link AccountView#localpart()}, when non-blank — the
     *       CANONICAL, admin-bff-persisted, collision-checked homeserver username
     *       (account-takeover-by-collision fix, Liquibase changeset 290 on admin-bff).
     *       {@code MatrixProxyController.localpart}/{@code MastodonProxyController.localpart}
     *       (the two homeserver-MINT call sites — {@code broker.mintMatrix}/{@code
     *       mintMastodon}) now read THIS claim first, falling back to the
     *       {@code preferred_username}/{@code sub} derivation only when it is absent (a
     *       real, non-bff_-session Casdoor JWT, which never runs through this filter at
     *       all). Threading it through the ALREADY-fetched {@link AccountView} here costs
     *       no additional admin-bff round trip — this filter resolves it via {@link
     *       AdminBffInternalClient#resolveSession} for every bff_-session request
     *       regardless. The OTHER {@code preferred_username}/{@code sub}-based localpart
     *       readers listed above ({@code ConnectedClientsController}, {@code
     *       SelfSilenceController}) are unchanged by this fix — they are not homeserver
     *       MINT call sites.</li>
     *   <li>{@code mastodon_localpart} = {@link AccountView#mastodonLocalpart()}, when
     *       non-blank — the coarser Mastodon fold (admin-bff changeset 291) with its OWN
     *       uniqueness. {@code MastodonProxyController.mastodonLocalpart} reads THIS claim
     *       (falling back to an internal account read only when absent), so a Mastodon mint is
     *       never a client-side re-fold of {@code localpart} — the residual half of the
     *       account-takeover-by-collision fix (the Matrix {@code localpart} above is 290's half).</li>
     *   <li>{@code iss} = {@link #singleTrustedIssuerOrNull} — see its own doc for the
     *       single- vs multi-issuer distinction this claim exists to serve.</li>
     * </ul>
     *
     * <p><b>Not populated:</b> {@code hs_token} (the homeserver-native-token claim
     * {@code ConnectedClientsController.homeserverBearer} reads) — {@code
     * AdminBffInternalClient}'s HTTP introspection contract carries no such field, and
     * that accessor's OWN doc already documents it as "Absent on the our-UI Casdoor
     * token... null-tolerant", i.e. already commonly absent even for a real JWT, so
     * leaving it unset here is consistent with existing behaviour, not a new gap.
     */
    private Jwt syntheticJwt(AccountView view) {
        List<String> claimRoles = view.registrationComplete() ? view.roles() : List.of();
        Jwt.Builder builder = Jwt.withTokenValue(SYNTHETIC_TOKEN_MARKER + view.id())
                .header("typ", "bff-synthetic-principal")
                .subject(view.id())
                .claim("roles", claimRoles);

        String handle = view.handle();
        if (handle != null && !handle.isBlank()) {
            if ("google".equalsIgnoreCase(view.provider())) {
                builder.claim("email", handle);
            } else {
                builder.claim("preferred_username", handle);
            }
        }

        // Account-takeover-by-collision fix: thread the CANONICAL, collision-checked
        // localpart through — see the class doc above.
        String localpart = view.localpart();
        if (localpart != null && !localpart.isBlank()) {
            builder.claim("localpart", localpart);
        }

        // The coarser Mastodon fold (admin-bff changeset 291): MastodonProxyController mints
        // under THIS claim, not a re-fold of `localpart` — two accounts distinct under the
        // Matrix fold still collapse to one Mastodon localpart, so the shared-password recover
        // leg would otherwise let the second take over the first (the residual half of the
        // takeover fix). No extra round trip — the AccountView already carries it.
        String mastodonLocalpart = view.mastodonLocalpart();
        if (mastodonLocalpart != null && !mastodonLocalpart.isBlank()) {
            builder.claim("mastodon_localpart", mastodonLocalpart);
        }

        String issuer = singleTrustedIssuerOrNull(domainRegistry);
        if (issuer != null) {
            builder.issuer(issuer);
        }

        return builder.build();
    }

    /**
     * The {@code iss} claim {@link #syntheticJwt} should stamp so {@code
     * Roles.domainOf(Jwt, DomainRegistry)} (read by {@code PrincipalDomain.forScope},
     * which 13 of the 16 Bug-2 controllers call) resolves the SAME brand-domain scope a
     * real Casdoor JWT for this account would — closing the previously-known "low"
     * finding that this filter's {@link Authentication} carried no {@code DOMAIN_}
     * authority at all.
     *
     * <p>Correctly recoverable ONLY in single-issuer mode. {@link AccountView} carries
     * no brand/domain field — only {@code provider}, the OAuth LOGIN provider
     * ({@code google}/{@code discord}/{@code casdoor}), a completely different axis from
     * the multi-BRAND per-Casdoor-instance concept {@link DomainRegistry} models — so a
     * genuinely multi-issuer deployment has no way to recover which brand's Casdoor a
     * {@code bff_} session's account belongs to from what admin-bff's introspection
     * response gives us. {@link DomainRegistry#trustedIssuers()} has EXACTLY one entry
     * in both the fully-unconfigured case (empty registry — {@code
     * DomainRegistry.domainOf} short-circuits to {@code DEFAULT_DOMAIN} without even
     * inspecting the {@code iss} argument, so leaving it unset there is harmless) and the
     * single-issuer-configured case (one real issuer URI seeded to {@code
     * DEFAULT_DOMAIN}); in BOTH, this returns that issuer (or {@code null}, which is
     * equally safe in the empty case). Only when {@link DomainRegistry#isMultiIssuer()}
     * (more than one trusted issuer) does this return {@code null} — no {@code iss}
     * claim is set, and {@code PrincipalDomain.forScope} then FAILS CLOSED (denies
     * domain-scoped rows, the {@code "__deny__"} sentinel) for a {@code bff_}-session
     * caller rather than guessing wrong. Documented, narrowed (not fully closed) gap:
     * single-issuer clusters (the common case) now resolve {@code DOMAIN_default}
     * correctly; true multi-brand deployments still deny domain-scoped {@code bff_}
     * -session reads/writes until a real brand-aware field is added to the introspection
     * contract.
     */
    private static String singleTrustedIssuerOrNull(DomainRegistry registry) {
        if (registry == null) {
            return null;
        }
        Set<String> trusted = registry.trustedIssuers();
        return trusted.size() == 1 ? trusted.iterator().next() : null;
    }

    /** Overload without the MFA flag — retained for the existing authority-mapping unit
     *  tests; equivalent to {@code buildAuthorities(view, false)}. */
    static List<GrantedAuthority> buildAuthorities(AccountView view) {
        return buildAuthorities(view, false);
    }

    /** Package-private (not private) so a unit test can exercise the mapping directly.
     *  Mirrors the gateway's {@code BffSessionAuthFilter.buildAuthorities} exactly: the
     *  {@code ROLE_USER} floor is always present; an incomplete registration gets ONLY the
     *  floor (no roles, no {@code MFA_SATISFIED}, even if the session's MFA is satisfied);
     *  otherwise each role maps to {@code ROLE_<UPPER>} (deduped against the floor) and
     *  {@link #MFA_SATISFIED} is appended when {@code mfaSatisfied}. */
    static List<GrantedAuthority> buildAuthorities(AccountView view, boolean mfaSatisfied) {
        var authorities = new ArrayList<GrantedAuthority>();
        authorities.add(new SimpleGrantedAuthority("ROLE_USER"));

        if (!view.registrationComplete()) {
            return authorities;
        }

        if (view.roles() != null) {
            for (String role : view.roles()) {
                if (role != null && !role.isBlank()) {
                    String authority = "ROLE_" + role.trim().toUpperCase();
                    if (!"ROLE_USER".equals(authority)) {
                        authorities.add(new SimpleGrantedAuthority(authority));
                    }
                }
            }
        }

        if (mfaSatisfied) {
            authorities.add(new SimpleGrantedAuthority(MFA_SATISFIED));
        }

        return authorities;
    }
}
