package systems.snapdragon.userbff.security;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The issuer→domain registry. Delineated:
 * <ul>
 *   <li><b>USER-SITUATIONAL</b> — single-issuer / no-config back-compat
 *       (everyone DOMAIN_default).</li>
 *   <li><b>MULTIUSER-SITUATIONAL</b> — multi-brand mapping (distinct issuers →
 *       distinct domains).</li>
 *   <li><b>CROSS-USER</b> — fail-CLOSED on an unknown issuer (multi-brand mode):
 *       null domain, not a silent default.</li>
 * </ul>
 */
class DomainRegistryTest {

    @Nested
    class UserSituational {
        @Test
        void noConfig_everyIssuerIsDefault() {
            DomainRegistry r = new DomainRegistry("", "");
            assertThat(r.domainOf("https://anything.example")).isEqualTo("default");
            assertThat(r.domainOf(null)).isEqualTo("default");
            assertThat(r.isMultiIssuer()).isFalse();
        }

        @Test
        void singleIssuer_mapsLoneIssuerToDefault() {
            DomainRegistry r = new DomainRegistry("https://id.snapdragon.systems", "");
            assertThat(r.domainOf("https://id.snapdragon.systems")).isEqualTo("default");
            // trailing slash tolerated
            assertThat(r.domainOf("https://id.snapdragon.systems/")).isEqualTo("default");
            assertThat(r.isMultiIssuer()).isFalse();
        }
    }

    @Nested
    class MultiuserSituational {
        private final DomainRegistry r = new DomainRegistry(
                "https://id.brandx.example",
                "https://id.brandx.example=brandx,https://id.brandy.example=brandy");

        @Test
        void distinctIssuersMapToDistinctBrands() {
            assertThat(r.domainOf("https://id.brandx.example")).isEqualTo("brandx");
            assertThat(r.domainOf("https://id.brandy.example")).isEqualTo("brandy");
            assertThat(r.isMultiIssuer()).isTrue();
            assertThat(r.trustedIssuers())
                    .containsExactlyInAnyOrder("https://id.brandx.example", "https://id.brandy.example");
        }
    }

    @Nested
    class CrossUser {
        private final DomainRegistry r = new DomainRegistry(
                "https://id.brandx.example",
                "https://id.brandx.example=brandx,https://id.brandy.example=brandy");

        @Test
        void unknownIssuer_failsClosed_null() {
            assertThat(r.domainOf("https://evil.attacker.example")).isNull();
            assertThat(r.isTrusted("https://evil.attacker.example")).isFalse();
        }

        @Test
        void trustedIssuers_areTrusted() {
            assertThat(r.isTrusted("https://id.brandx.example")).isTrue();
            assertThat(r.isTrusted("https://id.brandy.example")).isTrue();
        }
    }
}
