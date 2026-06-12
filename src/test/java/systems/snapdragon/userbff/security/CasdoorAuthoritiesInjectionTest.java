package systems.snapdragon.userbff.security;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The CANONICAL converter's security invariants — the authority-injection defense
 * COPIED from snapdragon-gateway. Delineated per the test standard:
 *
 * <ul>
 *   <li><b>USER-SITUATIONAL</b> — a single token's claims map to the right
 *       authorities (floor, roles, permissions, issuer-derived domain).</li>
 *   <li><b>CROSS-USER</b> — the ISOLATION KEYSTONE: a brand-X token must NOT be
 *       able to forge another brand's tenant scope ({@code DOMAIN_other}) or a
 *       super-role ({@code ROLE_SUPERADMIN}) by stuffing the {@code permissions}
 *       claim. These are the exact injection regressions the standard calls out.</li>
 * </ul>
 */
class CasdoorAuthoritiesInjectionTest {

    /** brandx issuer -> DOMAIN_brandx; brandy issuer -> DOMAIN_brandy. */
    private static final DomainRegistry MULTI = new DomainRegistry(
            "https://id.brandx.example",
            "https://id.brandx.example=brandx,https://id.brandy.example=brandy");

    /** Single-issuer (no tenancy config) -> every token DOMAIN_default. */
    private static final DomainRegistry SINGLE = new DomainRegistry("", "");

    private static Jwt.Builder base(String issuer) {
        Jwt.Builder b = Jwt.withTokenValue("t").header("alg", "none")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(3600))
                .subject("u");
        if (issuer != null) b = b.claim("iss", issuer).issuer(issuer);
        return b;
    }

    private static List<String> authorities(Jwt jwt, DomainRegistry registry) {
        return CasdoorAuthorities.authorities(jwt, registry).stream()
                .map(GrantedAuthority::getAuthority).toList();
    }

    // ── USER-SITUATIONAL ──────────────────────────────────────────────────────
    @Nested
    class UserSituational {

        @Test
        void floorPlusIssuerDomain() {
            assertThat(authorities(base("https://id.brandx.example").build(), MULTI))
                    .containsExactlyInAnyOrder("ROLE_USER", "DOMAIN_brandx");
        }

        @Test
        void singleIssuerIsDomainDefault() {
            assertThat(authorities(base(null).build(), SINGLE))
                    .containsExactlyInAnyOrder("ROLE_USER", "DOMAIN_default");
        }

        @Test
        void rolesBecomeRolePrefixedUpper_permissionsVerbatim() {
            Jwt jwt = base("https://id.brandx.example")
                    .claim("roles", List.of("admin"))
                    .claim("permissions", List.of("urn:games:play"))
                    .build();
            assertThat(authorities(jwt, MULTI))
                    .contains("ROLE_USER", "ROLE_ADMIN", "urn:games:play", "DOMAIN_brandx");
        }

        @Test
        void exactlyOneDomainAuthority() {
            long domains = authorities(base("https://id.brandy.example").build(), MULTI).stream()
                    .filter(a -> a.startsWith("DOMAIN_")).count();
            assertThat(domains).isEqualTo(1L);
        }
    }

    // ── CROSS-USER (the injection regressions) ────────────────────────────────
    @Nested
    class CrossUser {

        /** A brand-X token carrying permissions:["DOMAIN_brandy"] must NOT forge the
         *  other brand's tenant scope — the forged entry is DROPPED and the only
         *  DOMAIN_ authority is the validated-issuer one. */
        @Test
        void forgedDomainPermissionIsDropped() {
            Jwt jwt = base("https://id.brandx.example")
                    .claim("permissions", List.of("DOMAIN_brandy"))
                    .build();
            List<String> auth = authorities(jwt, MULTI);
            assertThat(auth).contains("DOMAIN_brandx");
            assertThat(auth).doesNotContain("DOMAIN_brandy");
            // exactly one DOMAIN_ authority — never the injected one.
            assertThat(auth.stream().filter(a -> a.startsWith("DOMAIN_")).count()).isEqualTo(1L);
            // Roles.domainOf must therefore resolve the validated brand, not fail.
            assertThat(Roles.domainOf(CasdoorAuthorities.authorities(jwt, MULTI))).isEqualTo("brandx");
        }

        /** permissions:["ROLE_SUPERADMIN"] must NOT forge the infra super-role. */
        @Test
        void forgedSuperadminPermissionIsDropped() {
            Jwt jwt = base("https://id.brandx.example")
                    .claim("permissions", List.of("ROLE_SUPERADMIN"))
                    .build();
            List<String> auth = authorities(jwt, MULTI);
            assertThat(auth).doesNotContain("ROLE_SUPERADMIN");
            assertThat(Roles.isSuperadmin(CasdoorAuthorities.authorities(jwt, MULTI))).isFalse();
        }

        /** Mixed case / whitespace must not sneak a reserved prefix past the guard. */
        @Test
        void forgedReservedPermission_caseAndSpaceInsensitive_isDropped() {
            Jwt jwt = base("https://id.brandx.example")
                    .claim("permissions", List.of("  role_superadmin ", "domain_brandy"))
                    .build();
            List<String> auth = authorities(jwt, MULTI);
            assertThat(auth).noneMatch(a -> a.toUpperCase().contains("SUPERADMIN"));
            assertThat(auth).doesNotContain("DOMAIN_brandy");
            assertThat(auth.stream().filter(a -> a.startsWith("DOMAIN_")).count()).isEqualTo(1L);
        }

        /** A roles entry "DOMAIN_x" becomes the INERT ROLE_DOMAIN_X (always ROLE_-
         *  prefixed first) — never a tenant DOMAIN_ authority. */
        @Test
        void rolesEntryCannotForgeDomain() {
            Jwt jwt = base("https://id.brandx.example")
                    .claim("roles", List.of("DOMAIN_brandy"))
                    .build();
            List<String> auth = authorities(jwt, MULTI);
            assertThat(auth).contains("ROLE_DOMAIN_BRANDY");   // inert, non-tenant
            assertThat(auth).doesNotContain("DOMAIN_brandy");
            assertThat(auth.stream().filter(a -> a.startsWith("DOMAIN_")).count()).isEqualTo(1L);
        }

        /** Even with a forged DOMAIN_ permission, the authority-list domain reader
         *  sees exactly one DOMAIN_ (the guard dropped the forgery) and resolves the
         *  real brand — the cross-tenant escalation is impossible. */
        @Test
        void domainOfAuthorities_resolvesValidatedBrand_notForgery() {
            Jwt jwt = base("https://id.brandy.example")
                    .claim("permissions", List.of("DOMAIN_brandx", "ROLE_SUPERADMIN"))
                    .build();
            assertThat(Roles.domainOf(CasdoorAuthorities.authorities(jwt, MULTI))).isEqualTo("brandy");
        }
    }
}
