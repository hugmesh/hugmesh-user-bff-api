package systems.snapdragon.userbff.config;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.core.ReactiveAdapterRegistry;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.reactive.result.method.annotation.AuthenticationPrincipalArgumentResolver;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.WebFilterChainProxy;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.server.ServerWebExchange;
import systems.snapdragon.userbff.web.ApiExceptionHandler;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.snapdragon.userbff.client.ConnectedClient;
import systems.snapdragon.userbff.client.ConnectedClientAuditRepository;
import systems.snapdragon.userbff.client.ConnectedClientsController;
import systems.snapdragon.userbff.client.ConnectedClientsService;
import systems.snapdragon.userbff.client.HomeserverClientsClient;
import systems.snapdragon.userbff.client.RevocationWriter;
import systems.snapdragon.userbff.security.DomainRegistry;
import systems.snapdragon.userbff.security.PrincipalDomain;
import systems.snapdragon.userbff.testsupport.TestIssuer;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * CROSS-DOMAIN HTTP-boundary test for {@link ConnectedClientsController} — closes
 * wave-2's gap: the graceful-degradation test
 * ({@code ConnectedClientsLiveHomeserverGracefulTest}) exercised only the best-effort
 * live-leg merge with a synthetic {@code mockJwt()} (NO issuer derivation), and the gate
 * test ({@code ConnectedClientsControllerGateTest}) mocked the WHOLE service. NEITHER
 * proved that the brand the controller hands the data layer is genuinely derived from the
 * token's cryptographically-VALIDATED {@code iss} — the cross-domain isolation path. Lives
 * in the {@code config} package (alongside {@code MultiIssuerSecuritySliceTest}) so it can
 * reuse {@link SecuritySliceSupport} + the package-private
 * {@link TenancyResourceServerConfig#tenantAuthManagerResolver()}; all
 * {@code ConnectedClients*} types it wires are public.
 *
 * <p>This runs REAL RS256 per-brand tokens through the REAL prod
 * {@link SecurityConfig#filterChain} (via {@link SecuritySliceSupport}, wired with the
 * REAL multi-issuer {@link TenancyResourceServerConfig#tenantAuthManagerResolver()}). Each
 * brand is backed by a {@link TestIssuer} — an in-process JWKS + OIDC-discovery server on
 * {@code 127.0.0.1} — so {@code fromIssuerLocation} validates real signed tokens with NO
 * network and NO live Casdoor. The controller drives the REAL {@link ConnectedClientsService}
 * + REAL {@link PrincipalDomain}; only the leaf seams are mocked
 * ({@link ConnectedClientAuditRepository}, {@link RevocationWriter}; the two
 * {@link HomeserverClientsClient} stubs are DISABLED so the durable repo is the sole data
 * path) — the brand therefore reaches the ACTUAL DURABLE REPO call we assert on.
 *
 * <p><b>The DENY is mutation-resistant at the REPO boundary — NOT a service mock.</b> We
 * assert {@code verify(repo).listForOwner(owner, "brandx")} AND
 * {@code verify(repo, never()).listForOwner(any, "brandy")}: the expected brand is the
 * string DERIVED FROM THE VALIDATED ISSUER, never re-derived from the same mock. If the
 * controller stopped passing {@code principalDomain.forScope(jwt)} (or routed an issuer to
 * the wrong brand), the {@code never()} verify on the foreign brand turns RED. owner is
 * always the token SUBJECT — never a path/body field.
 *
 * <ul>
 *   <li>brand-X token → {@code list}/{@code revoke} scoped to {@code "brandx"}; the repo is
 *       NEVER touched with {@code "brandy"} (brand-X cannot see brand-Y clients);</li>
 *   <li>brand-Y token → {@code "brandy"}, never {@code "brandx"} (isolation both ways);</li>
 *   <li>UNKNOWN issuer (well-formed, correctly signed, just NOT in
 *       {@code app.tenancy.issuers}) → 401 fail-closed BEFORE any controller code, so the
 *       repo is never touched (the multi-issuer resolver gives it no manager);</li>
 *   <li>garbage bearer / anonymous → 401, repo never touched.</li>
 * </ul>
 */
class ConnectedClientsControllerCrossDomainTest extends SecuritySliceSupport {

    /** A DISABLED stub seam (empty live stream) for a platform — the gated default, so the
     *  durable audit repo is the only data path and the brand it gets is the assertion. */
    private static final class DisabledSeam implements HomeserverClientsClient {
        private final String platform;
        DisabledSeam(String platform) { this.platform = platform; }
        @Override public String platform() { return platform; }
        @Override public Flux<ConnectedClient> list(String localpart, String bearer) { return Flux.empty(); }
        @Override public Mono<Boolean> revoke(String localpart, String externalRef, String bearer) {
            return Mono.just(false);
        }
    }

    private TestIssuer brandX;
    private TestIssuer brandY;
    private TestIssuer rogue;          // NOT trusted — absent from app.tenancy.issuers
    private ConnectedClientAuditRepository repo;
    private RevocationWriter revocations;
    private WebTestClient client;

    @BeforeEach
    void setUp() {
        brandX = new TestIssuer();
        brandY = new TestIssuer();
        rogue = new TestIssuer();

        // Multi-issuer registry: brand-X + brand-Y trusted; rogue is NOT listed.
        String issuersCsv = brandX.issuerUri() + "=brandx," + brandY.issuerUri() + "=brandy";
        DomainRegistry registry = new DomainRegistry(brandX.issuerUri(), issuersCsv);
        assertThat(registry.isMultiIssuer())
                .as("two trusted issuers => multi-issuer mode, the issuer->domain swap is live").isTrue();
        assertThat(registry.isTrusted(rogue.issuerUri()))
                .as("the rogue issuer is NOT trusted — its token must fail closed").isFalse();

        // REAL service wired with the REAL PrincipalDomain (issuer->domain) + mocked leaf
        // seams. Both homeserver seams are DISABLED, so the durable repo is the only data
        // source and the brand it receives is exactly what we assert.
        repo = mock(ConnectedClientAuditRepository.class);
        revocations = mock(RevocationWriter.class);
        ConnectedClientsService service = new ConnectedClientsService(
                repo,
                List.of(new DisabledSeam("matrix"), new DisabledSeam("mastodon")),
                revocations);
        ConnectedClientsController controller =
                new ConnectedClientsController(service, new PrincipalDomain(registry));

        // REAL multi-issuer resolver, built exactly as TenancyResourceServerConfig does.
        TenancyResourceServerConfig tenancy = new TenancyResourceServerConfig(registry, "", "", false, 600000L);
        ReactiveAuthenticationManagerResolver<ServerWebExchange> resolver =
                tenancy.tenantAuthManagerResolver();

        // Build the slice client THROUGH the prod SecurityConfig#filterChain (the same
        // seam SecuritySliceSupport.sliceClient uses), but additionally register the
        // @AuthenticationPrincipal argument resolver (the controller reads
        // `@AuthenticationPrincipal Jwt jwt`, not the context directly, unlike the
        // keystone probe controller) and the prod @RestControllerAdvice
        // (ApiExceptionHandler) so an ApiException.notFound maps to 404 exactly as in
        // production rather than surfacing as a 500.
        SecurityConfig securityConfig = new SecurityConfig(registry, present(resolver), false, 600000L);
        SecurityWebFilterChain chain = securityConfig.filterChain(ServerHttpSecurity.http());
        client = WebTestClient.bindToController(controller)
                .controllerAdvice(new ApiExceptionHandler())
                .argumentResolvers(c -> c.addCustomResolver(
                        new AuthenticationPrincipalArgumentResolver(ReactiveAdapterRegistry.getSharedInstance())))
                .webFilter(new WebFilterChainProxy(chain))
                .build();
    }

    @AfterEach
    void tearDown() {
        brandX.close();
        brandY.close();
        rogue.close();
    }

    /** One durable audit row for the given owner (the repo floor). */
    private static ConnectedClient auditRow(String owner) {
        return new ConnectedClient(UUID.randomUUID().toString(), owner, "matrix",
                ConnectedClient.KIND_DEVICE, "AUDIT-REF", "Audited Element", Instant.now(), null);
    }

    // ── brand-X: list/revoke scoped to brandx, never brandy ───────────────────

    @Test
    void list_brandXToken_scopesRepoToBrandX_neverBrandY() {
        when(repo.listForOwner(eq("alice"), eq("brandx"))).thenReturn(Flux.just(auditRow("alice")));

        String token = brandX.mint("alice", List.of("matrix_external_client"));
        client.get().uri("/bff/user/connected-clients")
                .header("Authorization", "Bearer " + token)
                .exchange()
                .expectStatus().isOk()
                .expectBodyList(ConnectedClient.class)
                .value(rows -> assertThat(rows).allSatisfy(r ->
                        assertThat(r.owner()).isEqualTo("alice")));   // owner == token subject

        // The brand handed to the durable repo is DERIVED from the validated issuer —
        // owner == token subject, domain == "brandx", and NEVER the foreign brand.
        verify(repo).listForOwner("alice", "brandx");
        verify(repo, never()).listForOwner(anyString(), eq("brandy"));
        verify(repo, never()).listForOwner(anyString(), eq("__deny__"));
    }

    @Test
    void revoke_brandXToken_scopesRepoToBrandX_neverBrandY() {
        String id = UUID.randomUUID().toString();
        // find() empty -> the service maps to 404, but the FIND is brand-scoped: that
        // brand-scoped repo call IS the cross-domain assertion (the 404 is incidental).
        when(repo.find(eq("alice"), eq(id), eq("brandx"))).thenReturn(Mono.empty());

        String token = brandX.mint("alice", List.of("matrix_external_client"));
        client.delete().uri("/bff/user/connected-clients/" + id)
                .header("Authorization", "Bearer " + token)
                .exchange()
                .expectStatus().isNotFound();   // no such row for this owner+brand

        verify(repo).find("alice", id, "brandx");
        verify(repo, never()).find(anyString(), anyString(), eq("brandy"));
        verify(repo, never()).find(anyString(), anyString(), eq("__deny__"));
    }

    // ── brand-Y: scoped to brandy, never brandx (isolation both ways) ──────────

    @Test
    void list_brandYToken_scopesRepoToBrandY_neverBrandX() {
        when(repo.listForOwner(eq("carol"), eq("brandy"))).thenReturn(Flux.just(auditRow("carol")));

        String token = brandY.mint("carol", List.of("mastodon_external_client"));
        client.get().uri("/bff/user/connected-clients")
                .header("Authorization", "Bearer " + token)
                .exchange()
                .expectStatus().isOk()
                .expectBodyList(ConnectedClient.class)
                .value(rows -> assertThat(rows).allSatisfy(r ->
                        assertThat(r.owner()).isEqualTo("carol")));

        verify(repo).listForOwner("carol", "brandy");
        verify(repo, never()).listForOwner(anyString(), eq("brandx"));
    }

    // ── UNKNOWN issuer: 401 fail-closed BEFORE the controller, repo untouched ──

    @Test
    void list_unknownIssuerToken_is401_failClosed_repoNeverTouched() {
        // A perfectly valid, correctly-signed token — just NOT in app.tenancy.issuers.
        // The per-issuer resolver returns Mono.empty() => 401 before any controller code,
        // so the repo is NEVER queried (not even with the __deny__ sentinel).
        String token = rogue.mint("mallory", List.of("matrix_external_client"));
        client.get().uri("/bff/user/connected-clients")
                .header("Authorization", "Bearer " + token)
                .exchange()
                .expectStatus().isUnauthorized();

        verify(repo, never()).listForOwner(anyString(), any());
    }

    @Test
    void list_garbageBearer_is401_repoNeverTouched() {
        client.get().uri("/bff/user/connected-clients")
                .header("Authorization", "Bearer not-a-jwt")
                .exchange()
                .expectStatus().isUnauthorized();
        verify(repo, never()).listForOwner(anyString(), any());
    }

    @Test
    void list_anonymous_is401_repoNeverTouched() {
        client.get().uri("/bff/user/connected-clients")
                .exchange()
                .expectStatus().isUnauthorized();
        verify(repo, never()).listForOwner(anyString(), any());
    }

    /** Wrap a resolver instance as the ObjectProvider SecurityConfig injects. */
    private static ObjectProvider<ReactiveAuthenticationManagerResolver<ServerWebExchange>> present(
            ReactiveAuthenticationManagerResolver<ServerWebExchange> resolver) {
        return SecuritySliceSupport.provider(resolver);
    }
}
