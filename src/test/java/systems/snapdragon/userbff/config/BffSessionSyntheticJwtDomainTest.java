package systems.snapdragon.userbff.config;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import systems.snapdragon.commons.security.DomainRegistry;
import systems.snapdragon.commons.security.Roles;
import systems.snapdragon.userbff.auth.AdminBffInternalClient;
import systems.snapdragon.userbff.auth.AdminBffInternalClient.AccountView;
import systems.snapdragon.userbff.security.PrincipalDomain;

import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Targeted coverage for {@link BffSessionAuthenticationWebFilter#syntheticJwt}'s {@code
 * iss}-claim decision (delegated to its private {@code singleTrustedIssuerOrNull}) —
 * the piece of the BUG 2 fix that closes the previously-known "low" finding that this
 * filter's {@link Authentication} carried no {@code DOMAIN_} authority, WITHOUT
 * silently mis-scoping a genuinely multi-brand deployment.
 *
 * <p>Exercises the REAL filter end-to-end (not the private helper directly — it has no
 * package-visible seam) against three {@link DomainRegistry} shapes and asserts what
 * {@link PrincipalDomain#forScope} — the same helper 13 of the 16 Bug-2 controllers call
 * — actually resolves for the resulting synthetic {@link Jwt}, since that is the
 * behaviour that matters, not the claim's raw presence.
 */
class BffSessionSyntheticJwtDomainTest {

    @SuppressWarnings("unchecked")
    private static ObjectProvider<AdminBffInternalClient> providerOf(AdminBffInternalClient client) {
        ObjectProvider<AdminBffInternalClient> provider = mock(ObjectProvider.class);
        when(provider.getIfAvailable()).thenReturn(client);
        return provider;
    }

    private static AdminBffInternalClient clientReturning(String token, AccountView view) {
        AdminBffInternalClient client = mock(AdminBffInternalClient.class);
        when(client.enabled()).thenReturn(true);
        when(client.resolveSession(token)).thenReturn(Mono.just(new AdminBffInternalClient.SessionResolution(view, "active", false)));
        return client;
    }

    /** Resolves the synthetic {@link Jwt} the filter writes to the SecurityContext for a
     *  {@code bff_} bearer, under the given {@link DomainRegistry}. */
    private static Jwt resolveJwt(DomainRegistry registry, AccountView view) {
        AdminBffInternalClient client = clientReturning("bff_tok", view);
        BffSessionAuthenticationWebFilter filter =
                new BffSessionAuthenticationWebFilter(providerOf(client), 3000L, registry);

        MockServerHttpRequest req = MockServerHttpRequest.get("/bff/user/profile")
                .header(HttpHeaders.AUTHORIZATION, "Bearer bff_tok")
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(req);
        AtomicReference<Authentication> captured = new AtomicReference<>();
        WebFilterChain chain = ex -> ReactiveSecurityContextHolder.getContext()
                .map(SecurityContext::getAuthentication)
                .doOnNext(captured::set)
                .then();

        StepVerifier.create(filter.filter(exchange, chain)).verifyComplete();
        return (Jwt) captured.get().getPrincipal();
    }

    // ── fully unconfigured registry (no issuer-uri, no app.tenancy.issuers) ─────

    @Test
    void emptyRegistry_domainStillResolvesDefault_regardlessOfIssClaim() {
        DomainRegistry registry = new DomainRegistry("", "");
        AccountView view = new AccountView("acct-1", "native", "h", true, List.of("user"));

        Jwt jwt = resolveJwt(registry, view);

        // DomainRegistry.domainOf short-circuits to DEFAULT_DOMAIN without even
        // inspecting the issuer argument when the map is empty, so this is safe
        // regardless of whether iss ends up set.
        assertThat(Roles.domainOf(jwt, registry)).isEqualTo(DomainRegistry.DEFAULT_DOMAIN);
        assertThat(new PrincipalDomain(registry).forScope(jwt)).isEqualTo(DomainRegistry.DEFAULT_DOMAIN);
    }

    // ── single-issuer configured registry (the common real deployment shape) ────

    @Test
    void singleIssuerRegistry_synthenticJwtCarriesRealIssuer_domainResolvesDefault() {
        String realIssuer = "https://casdoor.example.tld";
        DomainRegistry registry = new DomainRegistry(realIssuer, "");
        AccountView view = new AccountView("acct-2", "native", "h", true, List.of("user"));

        Jwt jwt = resolveJwt(registry, view);

        // The whole point of #singleTrustedIssuerOrNull: the synthetic Jwt's iss claim
        // must be the EXACT configured issuer string, or DomainRegistry's exact-match
        // lookup would miss and PrincipalDomain would fail closed to "__deny__" even
        // though this is single-issuer (the common) mode.
        assertThat(jwt.getIssuer()).hasToString(realIssuer);
        assertThat(Roles.domainOf(jwt, registry)).isEqualTo(DomainRegistry.DEFAULT_DOMAIN);
        assertThat(new PrincipalDomain(registry).forScope(jwt)).isEqualTo(DomainRegistry.DEFAULT_DOMAIN);
    }

    // ── genuinely multi-issuer registry — the documented, narrowed residual gap ──

    @Test
    void trueMultiIssuerRegistry_synteticJwtCarriesNoIssuer_domainFailsClosed_notBypassed() {
        String issuerA = "https://casdoor-brandx.example.tld";
        String issuerB = "https://casdoor-brandy.example.tld";
        DomainRegistry registry = new DomainRegistry("", issuerA + "=brandx," + issuerB + "=brandy");
        assertThat(registry.isMultiIssuer()).isTrue();
        AccountView view = new AccountView("acct-3", "native", "h", true, List.of("user"));

        Jwt jwt = resolveJwt(registry, view);

        // No brand is recoverable from AccountView (provider is the OAuth login
        // provider, e.g. google/discord/casdoor — a different axis from the Casdoor
        // per-brand instance DomainRegistry models) — so no iss claim is set...
        assertThat(jwt.getIssuer()).isNull();
        // ...and the domain resolution must FAIL CLOSED (deny), never bypass (null) and
        // never silently guess brandx or brandy.
        assertThat(Roles.domainOf(jwt, registry)).isNull();
        assertThat(new PrincipalDomain(registry).forScope(jwt))
                .as("a non-SUPERADMIN bff_-session caller in a genuinely multi-brand "
                        + "deployment must be denied domain-scoped rows, never bypassed")
                .isEqualTo("__deny__");
    }

    // ── SUPERADMIN still bypasses domain-scoping regardless of iss (unchanged) ──

    @Test
    void superadmin_stillBypassesDomainScope_evenInMultiIssuerMode() {
        String issuerA = "https://casdoor-brandx.example.tld";
        String issuerB = "https://casdoor-brandy.example.tld";
        DomainRegistry registry = new DomainRegistry("", issuerA + "=brandx," + issuerB + "=brandy");
        AccountView view = new AccountView("acct-4", "native", "h", true, List.of("superadmin"));

        Jwt jwt = resolveJwt(registry, view);

        assertThat(new PrincipalDomain(registry).forScope(jwt)).isNull(); // cross-domain bypass
    }
}
