package systems.snapdragon.userbff.security;

import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * D8 {@code MFA_SATISFIED} marker derivation — PARITY with snapdragon-gateway's
 * {@code CasdoorAuthoritiesTest} MFA cases (the canonical PR #40 source of truth),
 * package-adjusted to this BFF.
 *
 * <p>The marker is emitted ONLY from the BFF-written, freshness-validated
 * {@code mfa_satisfied_at} claim, behind {@code app.mfa.enabled} (ships DARK,
 * default off), as a NON-role authority, and NEVER from a roles/permissions entry.
 * An explicit {@code now} makes the freshness window deterministic.
 *
 * <ul>
 *   <li>USER-SITUATIONAL — a fresh stamp emits the marker; stale/future/blank does not.</li>
 *   <li>CROSS-USER / injection — a forged {@code permissions:["MFA_SATISFIED"]} is
 *       dropped by the reserved-prefix guard even with MFA enabled.</li>
 *   <li>Ships-dark — default-off NEVER emits the marker (byte-identical legacy set).</li>
 * </ul>
 */
class CasdoorAuthoritiesMfaTest {

    private static final long WINDOW = 600_000L;   // 10 min
    private static final long NOW = 1_750_000_000_000L;

    /** Single-issuer (no tenancy config) -> every token DOMAIN_default. */
    private static final DomainRegistry SINGLE = new DomainRegistry("http://casdoor:8000", "");

    private static Jwt jwt(String issuer, Map<String, Object> claims) {
        return Jwt.withTokenValue("test")
                .header("alg", "none")
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(60))
                .subject("u1")
                .issuer(issuer)
                .claims(c -> c.putAll(claims))
                .build();
    }

    private static Jwt mfaJwt(String satisfiedAt) {
        return jwt("http://casdoor:8000", Map.of("mfa_satisfied_at", satisfiedAt));
    }

    private static List<String> names(List<GrantedAuthority> a) {
        return a.stream().map(GrantedAuthority::getAuthority).toList();
    }

    // ── USER-SITUATIONAL ──────────────────────────────────────────────────────

    @Test
    void mfaEnabled_freshStamp_emitsMfaSatisfiedMarker_nonRole() {
        var on = new CasdoorAuthorities.MfaConfig(true, WINDOW);
        var auth = CasdoorAuthorities.authorities(
                mfaJwt(Long.toString(NOW - 60_000L)), SINGLE, on, NOW);
        assertThat(names(auth)).contains("MFA_SATISFIED");
        // NON-role authority — no ROLE_ prefix, so it can never satisfy a
        // hasRole()/route-access role check by accident.
        assertThat(names(auth)).doesNotContain("ROLE_MFA_SATISFIED");
    }

    @Test
    void mfaEnabled_staleOrFutureOrBlankStamp_noMarker() {
        var on = new CasdoorAuthorities.MfaConfig(true, WINDOW);
        // Stale (past the window).
        assertThat(names(CasdoorAuthorities.authorities(
                mfaJwt(Long.toString(NOW - WINDOW - 1)), SINGLE, on, NOW)))
                .doesNotContain("MFA_SATISFIED");
        // Future (forged-future / skew) — rejected.
        assertThat(names(CasdoorAuthorities.authorities(
                mfaJwt(Long.toString(NOW + 60_000L)), SINGLE, on, NOW)))
                .doesNotContain("MFA_SATISFIED");
        // Blank / non-numeric / non-positive — fail-closed.
        assertThat(names(CasdoorAuthorities.authorities(mfaJwt("   "), SINGLE, on, NOW)))
                .doesNotContain("MFA_SATISFIED");
        assertThat(names(CasdoorAuthorities.authorities(mfaJwt("not-a-number"), SINGLE, on, NOW)))
                .doesNotContain("MFA_SATISFIED");
        assertThat(names(CasdoorAuthorities.authorities(mfaJwt("0"), SINGLE, on, NOW)))
                .doesNotContain("MFA_SATISFIED");
        // Missing claim entirely.
        assertThat(names(CasdoorAuthorities.authorities(
                jwt("http://casdoor:8000", Map.of("roles", List.of("admin"))), SINGLE, on, NOW)))
                .doesNotContain("MFA_SATISFIED");
    }

    // ── Ships-dark (default off) — byte-identical legacy set ──────────────────

    @Test
    void mfaDisabled_darkDefault_neverEmitsMarker_evenWithFreshStamp() {
        // app.mfa.enabled=false (the dark default) => byte-identical legacy authority
        // set; the marker is NEVER produced even with a perfectly fresh stamp.
        var auth = CasdoorAuthorities.authorities(
                mfaJwt(Long.toString(NOW)), SINGLE,
                CasdoorAuthorities.MfaConfig.DISABLED, NOW);
        assertThat(names(auth)).doesNotContain("MFA_SATISFIED");
        // And the convenience overloads (legacy, no MfaConfig) are also dark.
        assertThat(names(CasdoorAuthorities.authorities(mfaJwt(Long.toString(NOW)), SINGLE)))
                .doesNotContain("MFA_SATISFIED");
    }

    // ── CROSS-USER / authority-injection defense ──────────────────────────────

    @Test
    void forgedMfaSatisfiedPermission_isDropped_evenWhenMfaEnabled() {
        // A forged permissions:["MFA_SATISFIED"] must NEVER inject the marker — the
        // reserved-prefix guard drops it; the marker comes ONLY from the validated
        // claim. Here there is NO valid mfa_satisfied_at claim, so the only way
        // MFA_SATISFIED could appear is via the forged permission (it must not).
        var on = new CasdoorAuthorities.MfaConfig(true, WINDOW);
        var auth = CasdoorAuthorities.authorities(
                jwt("http://casdoor:8000", Map.of(
                        "permissions", List.of("MFA_SATISFIED", "mfa_satisfied", " MFA_SATISFIED "))),
                SINGLE, on, NOW);
        assertThat(names(auth)).doesNotContain("MFA_SATISFIED");
        assertThat(names(auth)).noneMatch(s -> s.toUpperCase().contains("MFA_SATISFIED"));
    }

    @Test
    void forgedMfaSatisfiedPermission_doesNotSurvive_butValidClaimDoes() {
        // Both at once: a forged permission AND a genuine fresh claim. Exactly ONE
        // MFA_SATISFIED authority survives — the converter's, from the claim; the
        // permission entry is dropped (not double-added, not the source).
        var on = new CasdoorAuthorities.MfaConfig(true, WINDOW);
        var auth = CasdoorAuthorities.authorities(
                jwt("http://casdoor:8000", Map.of(
                        "mfa_satisfied_at", Long.toString(NOW),
                        "permissions", List.of("MFA_SATISFIED"))),
                SINGLE, on, NOW);
        assertThat(names(auth)).filteredOn(s -> s.equals("MFA_SATISFIED")).hasSize(1);
    }
}
