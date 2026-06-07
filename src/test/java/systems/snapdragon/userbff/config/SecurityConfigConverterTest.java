package systems.snapdragon.userbff.config;

import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import reactor.core.publisher.Flux;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit test for the Casdoor JWT → authority converter (same logic as
 * snapdragon-admin-bff-api / snapdragon-gateway): ROLE_USER floor; roles (string or
 * {name}) → ROLE_<UPPER>; permissions verbatim; isAdmin → ROLE_ADMIN.
 */
class SecurityConfigConverterTest {

    private List<String> authorities(Jwt jwt) {
        return SecurityConfig.casdoorAuthoritiesConverter()
                .convert(jwt)
                .map(GrantedAuthority::getAuthority)
                .collectList()
                .block();
    }

    private static Jwt.Builder base() {
        return Jwt.withTokenValue("t").header("alg", "none")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(3600))
                .subject("u");
    }

    @Test
    void floorIsRoleUser() {
        assertThat(authorities(base().build())).containsExactly("ROLE_USER");
    }

    @Test
    void stringRolesBecomeRolePrefixedUppercase() {
        Jwt jwt = base().claim("roles", List.of("admin", "mod")).build();
        assertThat(authorities(jwt)).contains("ROLE_USER", "ROLE_ADMIN", "ROLE_MOD");
    }

    @Test
    void objectRolesWithNameAreMapped() {
        Jwt jwt = base().claim("roles", List.of(Map.of("name", "admin"))).build();
        assertThat(authorities(jwt)).contains("ROLE_ADMIN");
    }

    @Test
    void permissionsArePassedThroughVerbatim() {
        Jwt jwt = base().claim("permissions", List.of("urn:games:play")).build();
        assertThat(authorities(jwt)).contains("urn:games:play");
    }

    @Test
    void isAdminTrueAddsRoleAdmin() {
        Jwt jwt = base().claim("isAdmin", true).build();
        assertThat(authorities(jwt)).contains("ROLE_ADMIN");
    }

    @Test
    void converterReturnsFlux() {
        Flux<GrantedAuthority> flux = SecurityConfig.casdoorAuthoritiesConverter().convert(base().build());
        assertThat(flux.collectList().block()).isNotEmpty();
    }
}
