package systems.snapdragon.userbff.config;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Profile;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverter;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import systems.snapdragon.commons.security.CasdoorAuthorities;
import systems.snapdragon.commons.security.DomainRegistry;
import systems.snapdragon.userbff.security.PrincipalDomain;

/**
 * Casdoor-aware OAuth2 resource-server security for the user BFF (reactive
 * WebFlux). {@code @EnableReactiveMethodSecurity} activates any {@code @PreAuthorize}
 * gates on the controllers. The JWT→authority mapping is delegated to the shared
 * {@link CasdoorAuthorities} converter — COPIED (logic) from the adversarially-
 * verified-safe snapdragon-gateway so the BFF and the gateway emit BYTE-IDENTICAL
 * authorities, including the reserved-prefix injection guard on {@code permissions}
 * and exactly one issuer-derived {@code DOMAIN_<x>} tenant authority.
 *
 * <p>This BFF's floor is {@code ROLE_USER}: the converter adds {@code ROLE_USER} to
 * every authenticated principal, so the entire {@code /bff/user/**} surface is gated
 * to "any authenticated caller" (i.e. ROLE_USER). Owner-enforcement (owner = JWT
 * subject) is applied IN the controllers/services — the security layer only proves
 * authentication, the service layer proves ownership AND domain-scope (a principal
 * only sees/mutates rows in its own {@code DOMAIN_<x>}; SUPERADMIN is unscoped).
 *
 * <p><b>SSO LOGIN RELOCATION.</b> user-bff now OWNS the login leg: the OIDC redirect
 * callback ({@code /bff/auth/callback}) plus the {@code /bff/login} / {@code /bff/register}
 * / {@code /bff/session} entrypoints are PRE-AUTH ({@code permitAll}) — they are how a
 * caller obtains the opaque {@code bff_} session in the first place, so they cannot
 * require the JWT they have not yet got. This whole surface SHIPS DARK behind
 * {@code app.bff.oidc.enabled=false} (every handler 503s / fail-closes when the flag is
 * off), so {@code permitAll} only EXPOSES the routes — it authenticates no one. The
 * authenticated read-back ({@code /bff/me}) deliberately stays behind the floor
 * (matches admin-bff).
 *
 * <p><b>Multi-issuer is OPT-IN + backward-compatible.</b> When
 * {@code app.tenancy.issuers} carries per-brand issuer=domain pairs
 * ({@link TenancyResourceServerConfig} contributes a resolver AND the registry is
 * {@link DomainRegistry#isMultiIssuer()}), each trusted per-brand Casdoor validates
 * its own tokens (unknown {@code iss} → 401). Otherwise the resource server stays on
 * the existing single {@code o.jwt(...)} issuer-uri path — byte-for-byte unchanged.
 */
@Configuration
@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
// SecurityConfig depends on the commons DomainRegistry (the converter stamps the
// issuer-derived DOMAIN_<x>); PrincipalDomain is the controllers' single
// domain-resolution bean. DomainRegistry + the config-gated multi-issuer
// TenancyResourceServerConfig now live in systems.snapdragon.commons.* (OUTSIDE the
// userbff component-scan), so they are pulled in via CommonsSecurityConfig's @Import;
// PrincipalDomain stays a userbff @Component but is imported here too so every
// @WebFluxTest slice that imports SecurityConfig gets it — the slice context loads
// without each test re-declaring them.
@Import({CommonsSecurityConfig.class, PrincipalDomain.class})
public class SecurityConfig {

    /** Issuer→domain source of truth. Injected so the converter can stamp the
     *  cryptographically-validated {@code iss} as a {@code DOMAIN_<x>} authority.
     *  Single-issuer clusters get a registry that maps the lone issuer (or no issuer
     *  at all) to {@code DOMAIN_default}, so behaviour is unchanged. */
    private final DomainRegistry domainRegistry;

    /** OPTIONAL per-brand multi-issuer resolver. Present (non-null provider value)
     *  ONLY when {@code app.tenancy.issuers} is configured, via
     *  {@link TenancyResourceServerConfig}. When absent the resource server stays on
     *  the single {@code o.jwt(...)} issuer-uri wiring — byte-for-byte the current
     *  single-issuer path. */
    private final ObjectProvider<ReactiveAuthenticationManagerResolver<ServerWebExchange>>
            tenantAuthManagerResolver;

    /** D8 MFA floor — whether the converter derives the {@code MFA_SATISFIED}
     *  marker at all. {@code app.mfa.enabled}, DEFAULT {@code false} (ships dark:
     *  when off the converter emits the legacy byte-identical authority set and
     *  {@code MFA_SATISFIED} is NEVER produced). */
    private final boolean mfaEnabled;

    /** D8 freshness window in millis for {@code Roles.isMfaSatisfied}.
     *  {@code app.mfa.freshness-window}, DEFAULT 600000 (10m). */
    private final long mfaFreshnessWindowMillis;

    public SecurityConfig(DomainRegistry domainRegistry,
                          ObjectProvider<ReactiveAuthenticationManagerResolver<ServerWebExchange>>
                                  tenantAuthManagerResolver,
                          @Value("${app.mfa.enabled:false}") boolean mfaEnabled,
                          @Value("${app.mfa.freshness-window:600000}") long mfaFreshnessWindowMillis) {
        this.domainRegistry = domainRegistry;
        this.tenantAuthManagerResolver = tenantAuthManagerResolver;
        this.mfaEnabled = mfaEnabled;
        this.mfaFreshnessWindowMillis = mfaFreshnessWindowMillis;
    }

    /**
     * SpringDoc OpenAPI spec + Swagger UI surface. {@code /v3/api-docs} is the raw
     * OpenAPI JSON the platform ng-openapi-gen typed clients (the paired
     * snapdragon-user-ui) + the docs pipeline fetch. Gated per profile (see the two
     * filter-chain beans): public under dev/test so {@code gen:fetch} can curl the
     * spec without a token, ROLE_ADMIN / SUPERADMIN everywhere else (prod) so the API
     * contract is never publicly reachable — matching the admin-bff template.
     */
    private static final String[] SPEC_PATHS = {
            "/v3/api-docs/**", "/swagger-ui/**", "/swagger-ui.html", "/webjars/swagger-ui/**"
    };

    /**
     * Shared route rules common to BOTH the dev/test and prod filter chains. The
     * ONLY difference between the two profiles is how {@link #SPEC_PATHS} is gated,
     * so every other route lives here to keep the two chains in lockstep and make it
     * impossible to loosen a non-spec route by editing only one chain.
     */
    /**
     * Reactive HTTP RESPONSE-HEADER hardening — the API-DEFENSIVE MINIMUM for a
     * pure-JSON BFF resource server, applied to EVERY {@link SecurityWebFilterChain}.
     *
     * <p>This BFF is NOT the TLS front door — it is a no-document JSON resource server
     * that ALWAYS sits behind the shared snapdragon-gateway, which emits the full
     * browser-policy set (HSTS / Permissions-Policy / COOP / CORP / the UI-shell CSP)
     * ONCE at the single TLS-terminating PEP so 12 configs can't drift (NIST 800-228
     * sec 3-4). So this chain deliberately OMITS HSTS (meaningless over plaintext
     * intra-mesh, and misleading to assert from a non-edge hop) and Permissions-Policy
     * (no document surface to govern). It re-asserts only the defense-in-depth minimum:
     *
     * <ul>
     *   <li><b>Content-Security-Policy: {@code default-src 'none'; frame-ancestors 'none'}</b>
     *       — a JSON API serves no document, scripts, or framed content; the lockdown CSP
     *       is belt-and-braces should a response ever be mis-typed as HTML.</li>
     *   <li>Spring's reactive SECURE DEFAULTS are KEPT, never disabled —
     *       {@code X-Content-Type-Options: nosniff}, {@code X-Frame-Options: DENY},
     *       {@code Cache-Control: no-store...}, and {@code Referrer-Policy: no-referrer}
     *       (made explicit here so a CSP/Referrer regression is visible).</li>
     * </ul>
     *
     * <p>Purely ADDITIVE: no authz rule, issuer validation, or the correct-by-design
     * {@code csrf.disable()} bearer posture is touched.
     */
    private static void hardenHeaders(ServerHttpSecurity.HeaderSpec h) {
        h.contentSecurityPolicy(csp -> csp.policyDirectives(
                        "default-src 'none'; frame-ancestors 'none'"))
                // Keep Spring's nosniff + X-Frame-Options:DENY + Cache-Control defaults
                // (NOT disabled); make Referrer-Policy:no-referrer explicit.
                .referrerPolicy(rp -> rp.policy(
                        org.springframework.security.web.server.header
                                .ReferrerPolicyServerHttpHeadersWriter.ReferrerPolicy.NO_REFERRER));
    }

    private static void commonRoutes(ServerHttpSecurity.AuthorizeExchangeSpec ex) {
        // Probes are public so k8s/Docker healthchecks need no token.
        ex.pathMatchers("/actuator/health", "/actuator/health/**", "/actuator/info").permitAll();
        // INTERNAL service-to-service surface — SERVICE PRINCIPAL ONLY. The deliver
        // endpoint takes its TARGET (domain, userSubject) from the request BODY (the
        // system acting on a user's behalf, NOT owner==caller), so it MUST be
        // unreachable by any human JWT — a human reaching it could spoof a notification
        // to ANY user (an IDOR). ROLE_SERVICE is the platform service-account role (a
        // Casdoor client-credentials token carries it; no human login does), the SAME
        // mechanism federation-api gates its internal oracle with. Deliberately NOT
        // hasAnyRole(SERVICE,ADMIN,SUPERADMIN): ADMIN/SUPERADMIN are human-reachable and
        // would re-open the IDOR. The role hierarchy (SUPERADMIN > ADMIN/MOD/USER, NO
        // edge to SERVICE) means even SUPERADMIN is DENIED here. Declared BEFORE the
        // /bff/user/** authenticated catch-all so it can never fall through to the
        // any-authenticated-user floor.
        ex.pathMatchers("/bff/user/internal/**").hasRole("SERVICE");
        // PRE-AUTH SSO LOGIN SURFACE (ships dark behind app.bff.oidc.enabled=false): the
        // OIDC redirect callback + the login/register/session entrypoints are reachable
        // WITHOUT a Casdoor JWT — they are how a caller OBTAINS a session in the first
        // place (the browser only ever holds the opaque bff_ session, never a JWT). When
        // the surface is dark these handlers all 503/fail-closed, so permitAll only
        // EXPOSES them, it does not authenticate anyone. Declared BEFORE the
        // /bff/user/** floor so they don't fall through to .authenticated(). NOTE:
        // /bff/me is deliberately NOT here — it stays authenticated (matches admin-bff),
        // falling through to the anyExchange().authenticated() catch-all below.
        ex.pathMatchers("/bff/auth/callback", "/bff/login", "/bff/register", "/bff/session").permitAll();
        // The entire user surface — ROLE_USER floor. The converter adds ROLE_USER to
        // every authenticated principal, so .authenticated() == the ROLE_USER floor.
        // Owner-enforcement (owner = JWT subject) AND domain-scope (DOMAIN_<x>) are
        // enforced in the services.
        ex.pathMatchers("/bff/user/**").authenticated();
    }

    /**
     * Dev / test profile: the OpenAPI spec + Swagger UI are PUBLIC so
     * {@code gen:fetch} (ng-openapi-gen) and the docs pipeline can curl
     * {@code /v3/api-docs} locally without a Casdoor token. Activate with
     * {@code SPRING_PROFILES_ACTIVE=dev} (or the {@code test} profile the slice tests
     * use). Every non-spec route is identical to prod.
     */
    @Bean
    @Profile({"dev", "test"})
    SecurityWebFilterChain devFilterChain(ServerHttpSecurity http) {
        return http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .headers(SecurityConfig::hardenHeaders)
                .authorizeExchange(ex -> {
                    commonRoutes(ex);
                    ex.pathMatchers(SPEC_PATHS).permitAll();
                    ex.anyExchange().authenticated();
                })
                .oauth2ResourceServer(this::resourceServer)
                .build();
    }

    /**
     * Production profile (default — active whenever neither {@code dev} nor
     * {@code test} is): the OpenAPI spec + Swagger UI require ROLE_ADMIN (or the
     * cross-domain SUPERADMIN super-role) so the API contract is never publicly
     * reachable. Mirrors the admin-bff profile split. Every non-spec route is
     * identical to dev/test.
     */
    @Bean
    @Profile("!dev & !test")
    SecurityWebFilterChain filterChain(ServerHttpSecurity http) {
        return http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .headers(SecurityConfig::hardenHeaders)
                .authorizeExchange(ex -> {
                    commonRoutes(ex);
                    ex.pathMatchers(SPEC_PATHS).hasAnyRole("ADMIN", "SUPERADMIN");
                    ex.anyExchange().authenticated();
                })
                .oauth2ResourceServer(this::resourceServer)
                .build();
    }

    /**
     * Wire the OAuth2 resource server. Multi-issuer is OPT-IN: swap to the per-issuer
     * authentication-manager resolver ONLY when BOTH a resolver was contributed by
     * {@link TenancyResourceServerConfig} AND the registry is genuinely multi-issuer
     * (more than the single back-compat entry). Gating on {@code isMultiIssuer()} —
     * not merely {@code resolver != null} — keeps a single-issuer cluster on the
     * EXISTING issuer-uri {@code o.jwt(...)} decoder path even if the tenancy
     * conditional ever activates with just the lone back-compat issuer. In true
     * multi-brand mode each trusted per-brand Casdoor validates its own tokens
     * (unknown iss -> 401, fail-closed).
     */
    private void resourceServer(ServerHttpSecurity.OAuth2ResourceServerSpec o) {
        ReactiveAuthenticationManagerResolver<ServerWebExchange> resolver =
                tenantAuthManagerResolver.getIfAvailable();
        if (resolver != null && domainRegistry.isMultiIssuer()) {
            o.authenticationManagerResolver(resolver);
        } else {
            o.jwt(j -> j.jwtAuthenticationConverter(jwtConverter()));
        }
    }

    /**
     * Method-security role hierarchy — SUPERADMIN-only edges. Deliberately MINIMAL:
     * SUPERADMIN is a strict superset of admin/mod/user, but {@code ROLE_ADMIN} and
     * {@code ROLE_MOD} are documented SIBLINGS (no {@code ADMIN > MOD} edge) and the
     * AND-intersection composites ({@code ROLE_*_EXTERNAL_CLIENT}, the platform
     * composites) are intentionally ABSENT — so a hierarchy can NEVER let a plain
     * ADMIN satisfy an intersection role. This bean only smooths {@code @PreAuthorize}
     * ergonomics + lets SUPERADMIN reach the admin-gated spec surface; the actual
     * cross-surface authorization (and the domain-scope) is enforced by the service
     * layer.
     */
    @Bean
    RoleHierarchy roleHierarchy() {
        return RoleHierarchyImpl.fromHierarchy(
                "ROLE_SUPERADMIN > ROLE_ADMIN\n" +
                "ROLE_SUPERADMIN > ROLE_MOD\n" +
                "ROLE_SUPERADMIN > ROLE_USER");
    }

    private ReactiveJwtAuthenticationConverter jwtConverter() {
        ReactiveJwtAuthenticationConverter converter = new ReactiveJwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(casdoorAuthoritiesConverter());
        return converter;
    }

    /**
     * Casdoor JWT → authorities conversion. Delegates to the shared
     * {@link CasdoorAuthorities} so the single-issuer path here and the optional
     * multi-issuer path ({@link TenancyResourceServerConfig}) stay byte-identical —
     * three claim sources ({@code roles} → {@code ROLE_<UPPER>}, {@code permissions}
     * verbatim MINUS reserved-prefix injection, legacy {@code isAdmin} →
     * {@code ROLE_ADMIN}), a {@code ROLE_USER} floor, plus exactly one issuer-derived
     * {@code DOMAIN_<x>} authority (NON-role; {@code DOMAIN_default} for the
     * single-issuer fallback so this cluster is unchanged).
     */
    Converter<Jwt, Flux<GrantedAuthority>> casdoorAuthoritiesConverter() {
        return CasdoorAuthorities.converter(domainRegistry,
                new CasdoorAuthorities.MfaConfig(mfaEnabled, mfaFreshnessWindowMillis));
    }
}
