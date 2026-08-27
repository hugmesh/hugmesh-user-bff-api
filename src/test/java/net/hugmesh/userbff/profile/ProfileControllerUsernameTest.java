package net.hugmesh.userbff.profile;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Instant;

import net.hugmesh.userbff.auth.CanonicalIdentityResolver;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Documents + locks in HOW THE CASDOOR LOGIN NAME IS OBTAINED FROM THE JWT
 * ({@link ProfileController#usernameOf(Jwt)}): the {@code casdoor_username} claim
 * (stamped by {@code BffSessionAuthenticationWebFilter} for a {@code bff_} session),
 * then Casdoor's {@code preferred_username} (the login name = the DNS label behind
 * {@code <username>.hugmesh.net}), then {@code name}, then the subject as a last
 * resort. The row key ({@code user_id}) remains the SUBJECT — these are distinct on
 * purpose.
 *
 * <p>REGRESSION HALF: every candidate must be SHAPED like a login name. A value bearing
 * {@code ':'} is a {@code provider:handle} account id and a value bearing {@code '@'} is
 * an email address; neither can be a Casdoor username (Casdoor forbids {@code '@'}
 * outright) or a DNS label, so both are SKIPPED and, if nothing else qualifies,
 * {@code usernameOf} returns {@code null} so the caller fails closed. Handing a composite
 * subject to Casdoor as {@code userName} is the "user doesn't exist" defect that was fixed
 * for the JWT-subject carrier and survived on the {@code bff_}-session one.
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

    // ── the bff_-session carrier: casdoor_username wins, and bad shapes never do ──

    @Test
    void prefersCasdoorUsernameClaim_overPreferredUsername() {
        // The bff_-session synthetic principal: preferred_username carries admin-bff's
        // account HANDLE (an email for most accounts), casdoor_username the real login name.
        Jwt jwt = base().claim(CanonicalIdentityResolver.CLAIM_CASDOOR_USERNAME, "alice")
                .claim("preferred_username", "alice@example.com")
                .build();
        assertThat(ProfileController.usernameOf(jwt)).isEqualTo("alice");
    }

    @Test
    void googleSyntheticPrincipal_compositeSubject_isRefused_notPassedOn() {
        // The exact defect shape: provider=google stamps `email` and NO preferred_username,
        // so the old implementation fell through to the subject — the composite account id —
        // and Casdoor was asked to set the password of "google:alice@example.com".
        Jwt jwt = Jwt.withTokenValue("t").header("alg", "none")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(3600))
                .subject("google:alice@example.com")
                .claim("email", "alice@example.com")
                .build();
        assertThat(ProfileController.usernameOf(jwt)).isNull();
    }

    @Test
    void googleSyntheticPrincipal_withTheCasdoorUsernameClaim_resolvesTheMintedLoginName() {
        Jwt jwt = Jwt.withTokenValue("t").header("alg", "none")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(3600))
                .subject("google:alice@example.com")
                .claim("email", "alice@example.com")
                .claim(CanonicalIdentityResolver.CLAIM_CASDOOR_USERNAME, "alice")
                .build();
        assertThat(ProfileController.usernameOf(jwt)).isEqualTo("alice");
    }

    @Test
    void emailShapedPreferredUsername_isSkipped_notSentToCasdoorAsAUsername() {
        // A native bff_ session: admin-bff keys the account by email > preferred_username,
        // so the handle it stamps into preferred_username is usually an EMAIL. Casdoor
        // usernames can never contain '@' — passing it on is a guaranteed refusal.
        Jwt jwt = Jwt.withTokenValue("t").header("alg", "none")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(3600))
                .subject("casdoor:alice@example.com")
                .claim("preferred_username", "alice@example.com")
                .build();
        assertThat(ProfileController.usernameOf(jwt)).isNull();
    }

    @Test
    void compositeSubject_neverBecomesTheUsername_forAnyProvider() {
        for (String composite : new String[]{"casdoor:alice", "discord:bob",
                "google:carol@example.com", "casdoor:3f2a-uuid"}) {
            Jwt jwt = Jwt.withTokenValue("t").header("alg", "none")
                    .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(3600))
                    .subject(composite).build();
            assertThat(ProfileController.usernameOf(jwt))
                    .as("composite subject %s must not be used as a Casdoor username", composite)
                    .isNull();
        }
    }

    @Test
    void realCasdoorJwt_isUnaffected_preferredUsernameStillWins() {
        // The working carrier must stay working: a genuine Casdoor access token carries
        // preferred_username = the login name and sub = the UUID.
        Jwt jwt = Jwt.withTokenValue("t").header("alg", "none")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(3600))
                .subject("9f2d1a34-0000-4bb8-9e11-casdoor-uuid")
                .claim("preferred_username", "alice")
                .claim("email", "alice@example.com")
                .build();
        assertThat(ProfileController.usernameOf(jwt)).isEqualTo("alice");
    }
}
