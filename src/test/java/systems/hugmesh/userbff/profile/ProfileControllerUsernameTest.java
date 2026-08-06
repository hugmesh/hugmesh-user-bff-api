package systems.hugmesh.userbff.profile;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Documents + locks in HOW THE VANITY USERNAME IS OBTAINED FROM THE JWT
 * ({@link ProfileController#usernameOf(Jwt)}): Casdoor's {@code preferred_username}
 * claim (the login name = the DNS label behind {@code <username>.hugmesh.systems}),
 * falling back to {@code name}, then to the subject only if neither is present. The
 * row key ({@code user_id}) remains the SUBJECT — these are distinct on purpose.
 */
class ProfileControllerUsernameTest {

    private static Jwt.Builder base() {
        return Jwt.withTokenValue("t").header("alg", "none")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(3600))
                .subject("sub-opaque-id");
    }

    @Test
    void prefersPreferredUsernameClaim() {
        Jwt jwt = base().claim("preferred_username", "alice").claim("name", "Alice Liddell").build();
        assertThat(ProfileController.usernameOf(jwt)).isEqualTo("alice");
    }

    @Test
    void fallsBackToNameClaim_whenNoPreferredUsername() {
        Jwt jwt = base().claim("name", "bob").build();
        assertThat(ProfileController.usernameOf(jwt)).isEqualTo("bob");
    }

    @Test
    void fallsBackToSubject_whenNoUsernameClaims() {
        // subject is an opaque id, NOT a username — last resort only.
        assertThat(ProfileController.usernameOf(base().build())).isEqualTo("sub-opaque-id");
    }

    @Test
    void blankPreferredUsername_fallsThrough() {
        Jwt jwt = base().claim("preferred_username", "  ").claim("name", "carol").build();
        assertThat(ProfileController.usernameOf(jwt)).isEqualTo("carol");
    }
}
