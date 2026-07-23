package systems.hugmesh.userbff.security;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;
import systems.hugmesh.commons.security.DomainRegistry;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The controller's single domain-resolution bean. Delineated:
 * <ul>
 *   <li><b>USER-SITUATIONAL</b> — a plain brand user resolves their issuer brand;
 *       single-issuer resolves "default".</li>
 *   <li><b>MULTIUSER-SITUATIONAL</b> — SUPERADMIN resolves the {@code null} bypass
 *       (sees every brand).</li>
 *   <li><b>CROSS-USER</b> — a non-SUPERADMIN whose issuer is UNKNOWN fails CLOSED to
 *       the non-matchable {@code __deny__} sentinel (never the null bypass).</li>
 * </ul>
 */
class PrincipalDomainTest {

    private static final DomainRegistry MULTI = new DomainRegistry(
            "https://id.brandx.example",
            "https://id.brandx.example=brandx,https://id.brandy.example=brandy");
    private static final DomainRegistry SINGLE = new DomainRegistry("", "");

    private static Jwt.Builder base(String issuer) {
        Jwt.Builder b = Jwt.withTokenValue("t").header("alg", "none")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(3600))
                .subject("u");
        if (issuer != null) b = b.claim("iss", issuer).issuer(issuer);
        return b;
    }

    @Nested
    class UserSituational {
        @Test
        void brandUser_resolvesIssuerBrand() {
            PrincipalDomain pd = new PrincipalDomain(MULTI);
            assertThat(pd.forScope(base("https://id.brandx.example").build())).isEqualTo("brandx");
        }

        @Test
        void singleIssuer_resolvesDefault() {
            PrincipalDomain pd = new PrincipalDomain(SINGLE);
            assertThat(pd.forScope(base(null).build())).isEqualTo("default");
        }
    }

    @Nested
    class MultiuserSituational {
        @Test
        void superadmin_resolvesNullBypass() {
            PrincipalDomain pd = new PrincipalDomain(MULTI);
            Jwt jwt = base("https://id.brandx.example").claim("roles", List.of("superadmin")).build();
            assertThat(pd.forScope(jwt)).isNull();          // null = no predicate = sees all brands
        }

        @Test
        void superadmin_hyphenAndUnderscoreSpellings() {
            PrincipalDomain pd = new PrincipalDomain(MULTI);
            assertThat(pd.forScope(base("https://id.brandx.example")
                    .claim("roles", List.of("super-admin")).build())).isNull();
            assertThat(pd.forScope(base("https://id.brandx.example")
                    .claim("roles", List.of("super_admin")).build())).isNull();
        }
    }

    @Nested
    class CrossUser {
        /** A non-SUPERADMIN whose issuer is NOT in the registry (multi-brand mode)
         *  must FAIL CLOSED to a non-matchable sentinel, NEVER the null bypass — an
         *  unresolved issuer denies, never escalates to cross-domain. */
        @Test
        void nonSuperadmin_unknownIssuer_failsClosedToDenySentinel() {
            PrincipalDomain pd = new PrincipalDomain(MULTI);
            Jwt jwt = base("https://evil.attacker.example").build();
            String scope = pd.forScope(jwt);
            assertThat(scope).isNotNull();                  // never the bypass
            assertThat(scope).isEqualTo("__deny__");        // a domain no real row carries
        }

        /** A NON-superadmin brand user can never reach the null bypass. */
        @Test
        void brandUser_isNeverTheNullBypass() {
            PrincipalDomain pd = new PrincipalDomain(MULTI);
            assertThat(pd.forScope(base("https://id.brandy.example").build())).isEqualTo("brandy");
        }
    }
}
