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
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClientRequestException;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import systems.snapdragon.userbff.auth.AdminBffInternalClient;
import systems.snapdragon.userbff.auth.AdminBffInternalClient.AccountView;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

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
 * {@code !registrationComplete}, ONLY the floor; otherwise each role maps to
 * {@code ROLE_<UPPER>}, deduplicated against the floor.
 *
 * <p><b>{@code MFA_SATISFIED} is deliberately OMITTED</b> — grep-verified: no
 * {@code @PreAuthorize}/{@code hasAuthority("MFA_SATISFIED")} gate exists anywhere in
 * user-bff-api's controllers today (every {@code @PreAuthorize} here is a plain
 * {@code hasRole(...)}), so there is nothing for it to satisfy. It is also not
 * currently PLUMBABLE: admin-bff's {@code /bff/internal/session/introspect} response
 * carries {@code mfaSatisfied}, but {@link AdminBffInternalClient#getAccountBySession}
 * discards everything from that response except the account id (see its private
 * {@code SessionIntrospect(String id)} projection) and re-fetches the account via
 * {@link AdminBffInternalClient#getAccount}, whose {@link AccountView} record has no
 * {@code mfaSatisfied} field at all. If an MFA-gated endpoint is ever added to this
 * service, plumbing that flag through will need either a new
 * {@code AdminBffInternalClient} method that reads the introspect response's own
 * {@code mfaSatisfied}/{@code status} fields directly, or extending
 * {@code SessionIntrospect}. Tracked as a documented gap, not a silent omission.
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

    /** Default bounded wait on the admin-bff introspection round-trip. {@code
     *  AdminBffInternalClient.getAccountBySession} sets no timeout of its own (unlike
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

    public BffSessionAuthenticationWebFilter(
            ObjectProvider<AdminBffInternalClient> adminBffClient,
            @Value("${app.bff-session-auth.introspection-timeout-ms:" + DEFAULT_INTROSPECTION_TIMEOUT_MS + "}")
            long introspectionTimeoutMs) {
        this.adminBffClient = adminBffClient;
        this.introspectionTimeout = Duration.ofMillis(introspectionTimeoutMs);
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
                .flatMap(maybeAuth -> maybeAuth.isPresent()
                        ? chain.filter(exchange).contextWrite(
                                ReactiveSecurityContextHolder.withAuthentication(maybeAuth.get()))
                        : chain.filter(exchange))
                .onErrorResume(IntrospectionFailure.class, ex -> failClosed(exchange, ex));
    }

    /**
     * Resolves the token to {@code Optional.of(authentication)} on success, {@code
     * Optional.empty()} on an unknown/expired session (mapped 401), or an error signal
     * (wrapped as {@link IntrospectionFailure}) for anything else. Composed entirely
     * BEFORE {@link #filter}'s {@code flatMap} that calls {@code chain.filter} — see the
     * exactly-once invariant discussion in the class doc.
     */
    private Mono<Optional<Authentication>> resolve(AdminBffInternalClient client, String token) {
        return client.getAccountBySession(token)
                .timeout(introspectionTimeout)
                // getAccountBySession() is documented to always emit exactly one AccountView
                // or error — but WebClient.bodyToMono() completes EMPTY (no item, no error)
                // for a 2xx response with no/blank body, which would otherwise fall straight
                // through map/onErrorResume/onErrorMap untouched (none of them run on an
                // empty completion) and leave filter()'s flatMap never invoked at all —
                // silently neither authenticating, passing through, NOR failing closed.
                // Treat that as a resolution failure too, so it lands in the same fail-closed
                // 503 branch as every other unexpected admin-bff response shape.
                .switchIfEmpty(Mono.error(new IllegalStateException(
                        "admin-bff introspection returned no body for a 2xx response")))
                .map(view -> Optional.of(authenticationFor(view)))
                .onErrorResume(ResponseStatusException.class, ex -> {
                    if (ex.getStatusCode().value() == HttpStatus.UNAUTHORIZED.value()) {
                        // Unknown/expired session — pass through unauthenticated.
                        return Mono.just(Optional.<Authentication>empty());
                    }
                    // Not the mapped-401 case (shouldn't normally happen — see
                    // getAccountBySession's own onErrorMap — but don't silently swallow
                    // an unexpected status either): fail closed like everything else.
                    return Mono.error(ex);
                })
                .onErrorMap(ex -> !(ex instanceof IntrospectionFailure), IntrospectionFailure::new);
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

    private static Authentication authenticationFor(AccountView view) {
        return new UsernamePasswordAuthenticationToken(view.id(), null, buildAuthorities(view));
    }

    /** Package-private (not private) so a unit test can exercise the mapping directly. */
    static List<GrantedAuthority> buildAuthorities(AccountView view) {
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

        return authorities;
    }
}
