package systems.hugmesh.userbff.config;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.WebFilterChainProxy;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.server.ServerWebExchange;
import systems.hugmesh.commons.security.DomainRegistry;
import systems.hugmesh.userbff.auth.AdminBffInternalClient;

/**
 * Shared scaffolding for the user-BFF SECURITY-SLICE tests — builds a
 * {@link WebTestClient} that drives a real controller THROUGH the production
 * {@link SecurityConfig#filterChain} (the actual {@code authorizeExchange} path
 * policy + the OAuth2 resource-server wiring), with NO full Spring Boot context.
 *
 * <p>COPIED from hugmesh-gateway's {@code config.SecuritySliceSupport} per
 * {@code docs/testing/MULTI-ISSUER-SLICE.md}; the only edits are the package and the
 * {@link DomainRegistry} import — this BFF's {@code SecurityConfig} has the IDENTICAL
 * {@code (DomainRegistry, ObjectProvider<...>)} constructor and a
 * {@code filterChain(ServerHttpSecurity)} bean method (the prod {@code !dev & !test}
 * chain), so the seam transfers verbatim.
 *
 * <p><b>Which filter-chain.</b> This BFF declares TWO profile-gated chains —
 * {@code devFilterChain} ({@code dev}/{@code test}, OpenAPI spec public) and
 * {@code filterChain} ({@code !dev & !test}, the prod chain, OpenAPI spec
 * ROLE_ADMIN). We build {@code filterChain} (prod) so the slice exercises the MOST
 * RESTRICTIVE posture; both chains share the identical {@code commonRoutes()}
 * ({@code /bff/user/**} ROLE_USER floor, {@code /bff/user/internal/**} ROLE_SERVICE,
 * health public), so the path-gate assertions hold on either.
 *
 * <p>This is the load-bearing half of the copyable multi-issuer pattern: a
 * resource-server repo replicates the slice by (1) constructing its own
 * {@code SecurityConfig.filterChain} the same way here, (2) supplying
 * issuer-specific tokens via {@link systems.hugmesh.userbff.testsupport.TestIssuer},
 * and (3) asserting authority emission / 401 fail-closed against {@code WebTestClient}.
 */
abstract class SecuritySliceSupport {

    /**
     * Build a {@link WebTestClient} bound to {@code controllers}, routed THROUGH the
     * real {@link SecurityConfig#filterChain} built from a fresh
     * {@link ServerHttpSecurity}. The chain is installed as a {@link WebFilterChainProxy}
     * web filter so the resource-server authentication + the {@code authorizeExchange}
     * policy run exactly as in production.
     *
     * @param registry        the issuer-&gt;domain registry (single- or multi-issuer)
     * @param tenantResolver  the OPTIONAL per-issuer resolver provider — pass
     *                        {@link #provider(Object)} with the real resolver to take
     *                        the multi-issuer swap, or {@link #absent()} to stay on
     *                        the single-issuer {@code o.jwt(...)} path
     * @param controllers     the @RestController instances under test
     */
    static WebTestClient sliceClient(
            DomainRegistry registry,
            ObjectProvider<ReactiveAuthenticationManagerResolver<ServerWebExchange>> tenantResolver,
            Object... controllers) {

        SecurityConfig config = new SecurityConfig(registry, tenantResolver, false, 600000L);
        SecurityWebFilterChain chain = config.filterChain(ServerHttpSecurity.http());
        WebFilterChainProxy securityFilter = new WebFilterChainProxy(chain);

        return WebTestClient.bindToController(controllers)
                .webFilter(securityFilter)
                .build();
    }

    /**
     * Like {@link #sliceClient}, but ALSO installs {@link BffSessionAuthenticationWebFilter}
     * IN FRONT OF the security filter (array order = execution order for {@code
     * WebTestClient.webFilter(WebFilter...)}, confirmed empirically — the first vararg
     * runs first), exactly mirroring production {@code @Order} intent (bridge filter at
     * {@code HIGHEST_PRECEDENCE + 10}, ahead of Spring Security's own authentication
     * slot) without depending on {@code @Order} annotation processing, which this
     * bind-to-controller harness (no full Spring context) never performs anyway.
     *
     * @param adminBffClient the (mocked) internal client provider driving the bridge
     *                       filter's session resolution — see {@link #provider(Object)}
     *                       for a live client or {@link #absent()} for "no bridging
     *                       capability" (pass-through) coverage
     */
    static WebTestClient sliceClientWithBffSessionAuth(
            DomainRegistry registry,
            ObjectProvider<ReactiveAuthenticationManagerResolver<ServerWebExchange>> tenantResolver,
            ObjectProvider<AdminBffInternalClient> adminBffClient,
            Object... controllers) {

        SecurityConfig config = new SecurityConfig(registry, tenantResolver, false, 600000L);
        SecurityWebFilterChain chain = config.filterChain(ServerHttpSecurity.http());
        WebFilterChainProxy securityFilter = new WebFilterChainProxy(chain);
        BffSessionAuthenticationWebFilter bffFilter =
                new BffSessionAuthenticationWebFilter(adminBffClient, 3000L, registry);

        return WebTestClient.bindToController(controllers)
                .webFilter(bffFilter, securityFilter)
                .build();
    }

    /** An {@link ObjectProvider} that yields the given value from
     *  {@code getIfAvailable()} (what {@code SecurityConfig} calls). */
    @SuppressWarnings("unchecked")
    static <T> ObjectProvider<T> provider(T value) {
        return new ObjectProvider<>() {
            @Override public T getObject() { return value; }
            @Override public T getObject(Object... args) { return value; }
            @Override public T getIfAvailable() { return value; }
            @Override public T getIfUnique() { return value; }
        };
    }

    /** An empty {@link ObjectProvider} ({@code getIfAvailable()} returns {@code null})
     *  — the single-issuer path, where no tenant resolver was contributed. */
    static <T> ObjectProvider<T> absent() {
        return new ObjectProvider<>() {
            @Override public T getObject() { throw new IllegalStateException("no value"); }
            @Override public T getObject(Object... args) { throw new IllegalStateException("no value"); }
            @Override public T getIfAvailable() { return null; }
            @Override public T getIfUnique() { return null; }
        };
    }
}
