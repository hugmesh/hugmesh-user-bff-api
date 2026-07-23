package systems.hugmesh.userbff.config;

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
import systems.hugmesh.commons.security.DomainRegistry;
import systems.hugmesh.commons.security.Roles;
import systems.hugmesh.userbff.auth.AdminBffInternalClient;
import systems.hugmesh.userbff.auth.AdminBffInternalClient.AccountView;
import systems.hugmesh.userbff.security.PrincipalDomain;

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
        AccountView view = new AccountView("acct-1", "native", "h", true, List.of("user"), "lp");

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
        AccountView view = new AccountView("acct-2", "native", "h", true, List.of("user"), "lp");

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
        AccountView view = new AccountView("acct-3", "native", "h", true, List.of("user"), "lp");

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

    // ── changeset 301: a brand-aware account RESOLVES its brand on a multi-brand cluster ──

    /** An account carrying a brand — the changeset-301 introspect field, folded into the view
     *  by {@code AdminBffInternalClient#resolveSession}. */
    private static AccountView viewWithIssuer(String id, String issuer) {
        return new AccountView(id, "native", "h", true, List.of("user"), "lp", "", issuer);
    }

    @Test
    void multiIssuerRegistry_accountCarryingTrustedIssuer_resolvesThatBrand_notDeny() {
        // THE FIX. Pre-301 this exact shape resolved "__deny__" (see the test above): the
        // introspect contract carried no brand, so no iss was stamped. Now the account's own
        // VALIDATED issuer is preferred and the caller resolves ITS brand — the multi-brand
        // deployment finally works for native-login sessions.
        String issuerA = "https://casdoor-brandx.example.tld";
        String issuerB = "https://casdoor-brandy.example.tld";
        DomainRegistry registry = new DomainRegistry("", issuerA + "=brandx," + issuerB + "=brandy");
        assertThat(registry.isMultiIssuer()).isTrue();

        Jwt jwt = resolveJwt(registry, viewWithIssuer("acct-x", issuerA));

        assertThat(jwt.getIssuer()).hasToString(issuerA);
        assertThat(Roles.domainOf(jwt, registry)).isEqualTo("brandx");
        assertThat(new PrincipalDomain(registry).forScope(jwt)).isEqualTo("brandx");
    }

    @Test
    void multiIssuerRegistry_theOtherBrandsAccount_resolvesTheOtherBrand_noCrossTalk() {
        // The discriminator really discriminates: brandy's account must resolve brandy, not
        // brandx and not a first-entry default.
        String issuerA = "https://casdoor-brandx.example.tld";
        String issuerB = "https://casdoor-brandy.example.tld";
        DomainRegistry registry = new DomainRegistry("", issuerA + "=brandx," + issuerB + "=brandy");

        Jwt jwt = resolveJwt(registry, viewWithIssuer("acct-y", issuerB));

        assertThat(Roles.domainOf(jwt, registry)).isEqualTo("brandy");
        assertThat(new PrincipalDomain(registry).forScope(jwt)).isEqualTo("brandy");
    }

    @Test
    void multiIssuerRegistry_trailingSlashIssuer_stillResolvesTheBrand() {
        // DomainRegistry strips a trailing slash from its keys; the stamped claim must be the
        // canonical key form or the exact-match lookup misses and a legitimate caller is denied.
        String issuerA = "https://casdoor-brandx.example.tld";
        String issuerB = "https://casdoor-brandy.example.tld";
        DomainRegistry registry = new DomainRegistry("", issuerA + "=brandx," + issuerB + "=brandy");

        Jwt jwt = resolveJwt(registry, viewWithIssuer("acct-slash", issuerA + "/"));

        assertThat(jwt.getIssuer()).hasToString(issuerA);
        assertThat(new PrincipalDomain(registry).forScope(jwt)).isEqualTo("brandx");
    }

    // ── changeset 301: everything unverifiable degrades to EXACTLY the pre-301 deny ──

    @Test
    void multiIssuerRegistry_accountCarryingUNTRUSTEDIssuer_failsClosed_exactlyAsBefore() {
        // *** THE SECURITY TEST (consumer half). *** A forged/unknown issuer must NOT be
        // stamped: it names no brand this deployment trusts. It must degrade to precisely the
        // pre-301 behavior — no iss, "__deny__" — never resolve a brand, never bypass.
        String issuerA = "https://casdoor-brandx.example.tld";
        String issuerB = "https://casdoor-brandy.example.tld";
        DomainRegistry registry = new DomainRegistry("", issuerA + "=brandx," + issuerB + "=brandy");

        Jwt jwt = resolveJwt(registry, viewWithIssuer("acct-evil", "https://evil.attacker.tld"));

        assertThat(jwt.getIssuer()).as("an untrusted issuer must never be stamped").isNull();
        assertThat(Roles.domainOf(jwt, registry)).isNull();
        assertThat(new PrincipalDomain(registry).forScope(jwt)).isEqualTo("__deny__");
    }

    @Test
    void multiIssuerRegistry_blankIssuer_failsClosed_exactlyAsBefore() {
        // The legacy/older-admin-bff shape (field absent or null on the wire → blank in the
        // view): byte-identical to the pre-301 deny.
        String issuerA = "https://casdoor-brandx.example.tld";
        String issuerB = "https://casdoor-brandy.example.tld";
        DomainRegistry registry = new DomainRegistry("", issuerA + "=brandx," + issuerB + "=brandy");

        Jwt jwt = resolveJwt(registry, viewWithIssuer("acct-blank", ""));

        assertThat(jwt.getIssuer()).isNull();
        assertThat(new PrincipalDomain(registry).forScope(jwt)).isEqualTo("__deny__");
    }

    @Test
    void singleIssuerRegistry_untrustedAccountIssuer_stillFallsBackToTheConfiguredIssuer() {
        // Fallback semantics on the COMMON deployment shape: an account carrying a bogus brand
        // must not poison single-issuer mode — it falls through to singleTrustedIssuerOrNull
        // and resolves DEFAULT_DOMAIN exactly as it did pre-301.
        String realIssuer = "https://casdoor.example.tld";
        DomainRegistry registry = new DomainRegistry(realIssuer, "");

        Jwt jwt = resolveJwt(registry, viewWithIssuer("acct-bogus", "https://evil.attacker.tld"));

        assertThat(jwt.getIssuer()).hasToString(realIssuer);
        assertThat(new PrincipalDomain(registry).forScope(jwt)).isEqualTo(DomainRegistry.DEFAULT_DOMAIN);
    }

    @Test
    void emptyRegistry_accountIssuerIsNeverTrusted_theIsTrustedFailOpenGuard() {
        // DomainRegistry#isTrusted fails OPEN on an empty registry (domainOf short-circuits to
        // DEFAULT_DOMAIN without inspecting iss), so a membership test written with it would
        // stamp this attacker-chosen issuer. issuerFor uses strict non-empty-set containment,
        // so the claim is never stamped; domain still resolves DEFAULT_DOMAIN because the
        // unconfigured registry ignores iss entirely.
        DomainRegistry unconfigured = new DomainRegistry("", "");
        assertThat(unconfigured.isTrusted("https://evil.attacker.tld"))
                .as("guard premise: isTrusted DOES fail open on an empty registry")
                .isTrue();

        Jwt jwt = resolveJwt(unconfigured, viewWithIssuer("acct-noconf", "https://evil.attacker.tld"));

        assertThat(jwt.getIssuer()).as("never stamp an attacker-chosen iss").isNull();
        assertThat(new PrincipalDomain(unconfigured).forScope(jwt))
                .isEqualTo(DomainRegistry.DEFAULT_DOMAIN);
    }

    // ── SUPERADMIN still bypasses domain-scoping regardless of iss (unchanged) ──

    @Test
    void superadmin_stillBypassesDomainScope_evenInMultiIssuerMode() {
        String issuerA = "https://casdoor-brandx.example.tld";
        String issuerB = "https://casdoor-brandy.example.tld";
        DomainRegistry registry = new DomainRegistry("", issuerA + "=brandx," + issuerB + "=brandy");
        AccountView view = new AccountView("acct-4", "native", "h", true, List.of("superadmin"), "lp");

        Jwt jwt = resolveJwt(registry, view);

        assertThat(new PrincipalDomain(registry).forScope(jwt)).isNull(); // cross-domain bypass
    }
}
