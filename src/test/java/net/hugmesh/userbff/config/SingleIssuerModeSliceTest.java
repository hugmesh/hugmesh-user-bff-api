package net.hugmesh.userbff.config;

import org.junit.jupiter.api.Test;
import net.hugmesh.commons.security.DomainRegistry;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Single-issuer back-compat slice — proves a cluster with NO per-brand
 * {@code app.tenancy.issuers} stays OFF the multi-issuer resolver and on the plain
 * single {@code o.jwt(...)} decoder path, so the multi-issuer wiring is strictly
 * OPT-IN and byte-for-byte backward compatible.
 *
 * <p>The swap in {@link SecurityConfig#resourceServer} is gated on BOTH a contributed
 * resolver AND {@link DomainRegistry#isMultiIssuer()}. {@code isMultiIssuer()} is the
 * single observable that decides the branch: this asserts it is {@code false} for the
 * single-issuer and no-issuer configurations (so the swap is never taken), and the
 * lone configured issuer still maps to {@code DOMAIN_default}.
 *
 * <p>Category: USER-SITUATIONAL — the legacy single-tenant deployment's posture is
 * unchanged.
 */
class SingleIssuerModeSliceTest {

    @Test
    void singleConfiguredIssuer_isNotMultiIssuer_andMapsToDefaultDomain() {
        // One issuer-uri, empty app.tenancy.issuers => single-issuer mode. The swap is
        // NOT taken (SecurityConfig keeps the plain o.jwt(...) decoder), and the lone
        // issuer maps to DOMAIN_default.
        DomainRegistry registry = new DomainRegistry("http://127.0.0.1:9/realms/lone", "");
        assertThat(registry.isMultiIssuer())
                .as("a single configured issuer is NOT multi-issuer — the resolver swap is skipped")
                .isFalse();
        assertThat(registry.domainOf("http://127.0.0.1:9/realms/lone"))
                .isEqualTo(DomainRegistry.DEFAULT_DOMAIN);
    }

    @Test
    void noIssuerConfigured_isNotMultiIssuer_andEverythingMapsToDefault() {
        // No issuer at all (a bare local profile) => still single-issuer; every issuer
        // resolves to DOMAIN_default (the legacy single-tenant fallback).
        DomainRegistry registry = new DomainRegistry("", "");
        assertThat(registry.isMultiIssuer()).isFalse();
        assertThat(registry.domainOf("http://anything")).isEqualTo(DomainRegistry.DEFAULT_DOMAIN);
    }

    @Test
    void oneTenancyPair_isStillNotMultiIssuer() {
        // Exactly ONE issuer=domain pair is still treated as single-issuer
        // (isMultiIssuer requires MORE than the lone back-compat entry), so even a
        // 1-entry tenancy CSV keeps the plain decoder path.
        DomainRegistry registry = new DomainRegistry("", "http://127.0.0.1:9/realms/x=brandx");
        assertThat(registry.isMultiIssuer())
                .as("one tenancy pair is not yet multi-brand — the swap stays off")
                .isFalse();
        assertThat(registry.domainOf("http://127.0.0.1:9/realms/x")).isEqualTo("brandx");
    }
}
