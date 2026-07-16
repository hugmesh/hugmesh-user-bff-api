package systems.snapdragon.userbff.auth;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit test for the shared {@link CanonicalIdentityResolver} -- the single place the
 * account-takeover-by-collision policy lives. Proves claim-first, own-{@code casdoor:}-key
 * resolution (with the {@code email > preferred_username > sub} precedence admin-bff persists
 * under), the takeover invariant (never a foreign provider-namespace account), and fail-closed
 * vs best-effort terminals.
 */
class CanonicalIdentityResolverTest {

    private static Jwt jwt(String subject, Map<String, Object> claims) {
        Jwt.Builder b = Jwt.withTokenValue("real-casdoor-jwt")
                .header("alg", "none")
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(3600))
                .subject(subject);
        claims.forEach(b::claim);
        return b.build();
    }

    private static AdminBffInternalClient.AccountView view(String id, String localpart, String mastodon) {
        return new AdminBffInternalClient.AccountView(id, "casdoor", id, true, List.of("user"),
                localpart, mastodon);
    }

    private static WebClientResponseException notFound() {
        return WebClientResponseException.create(404, "Not Found", HttpHeaders.EMPTY, new byte[0], null);
    }

    // -- claim-first (bff_ synthetic principal) --------------------------------------------

    @Test
    void claimPresent_matrixAndMastodonUseDistinctStampedClaims_noAdminBffHop() {
        AdminBffInternalClient adminBff = mock(AdminBffInternalClient.class);
        CanonicalIdentityResolver r = new CanonicalIdentityResolver(adminBff);
        Jwt j = jwt("casdoor:uuid", Map.of(
                "localpart", "mx-lp", "mastodon_localpart", "md-lp", "preferred_username", "ignored"));

        StepVerifier.create(r.matrixLocalpart(j)).expectNext("mx-lp").verifyComplete();
        StepVerifier.create(r.mastodonLocalpart(j)).expectNext("md-lp").verifyComplete();

        verify(adminBff, never()).getAccount(anyString());
    }

    // -- own casdoor: key resolution + subject precedence ----------------------------------

    @Test
    void realJwt_emailWinsSubjectPrecedence_resolvesOwnCasdoorAccountLocalpart() {
        AdminBffInternalClient adminBff = mock(AdminBffInternalClient.class);
        when(adminBff.getAccount("casdoor:alice@x.com")).thenReturn(Mono.just(
                view("casdoor:alice@x.com", "alice-mx", "alice_md")));
        CanonicalIdentityResolver r = new CanonicalIdentityResolver(adminBff);
        // email AND preferred_username AND sub all present -> email must win.
        Jwt j = jwt("uuid-sub", Map.of("email", "alice@x.com", "preferred_username", "alice"));

        StepVerifier.create(r.matrixLocalpart(j)).expectNext("alice-mx").verifyComplete();
        StepVerifier.create(r.mastodonLocalpart(j)).expectNext("alice_md").verifyComplete();
        verify(adminBff, never()).getAccount("casdoor:alice");
        verify(adminBff, never()).getAccount("casdoor:uuid-sub");
    }

    @Test
    void realJwt_noEmail_preferredUsernameUsed_thenSub() {
        AdminBffInternalClient adminBff = mock(AdminBffInternalClient.class);
        when(adminBff.getAccount("casdoor:bob")).thenReturn(Mono.just(view("casdoor:bob", "bob-mx", "")));
        CanonicalIdentityResolver r = new CanonicalIdentityResolver(adminBff);
        Jwt j = jwt("uuid-sub", Map.of("preferred_username", "bob"));
        StepVerifier.create(r.matrixLocalpart(j)).expectNext("bob-mx").verifyComplete();

        // Only sub present -> casdoor:<sub>.
        AdminBffInternalClient adminBff2 = mock(AdminBffInternalClient.class);
        when(adminBff2.getAccount("casdoor:uuid-sub")).thenReturn(Mono.just(view("casdoor:uuid-sub", "sub-mx", "")));
        CanonicalIdentityResolver r2 = new CanonicalIdentityResolver(adminBff2);
        Jwt j2 = jwt("uuid-sub", Map.of());
        StepVerifier.create(r2.matrixLocalpart(j2)).expectNext("sub-mx").verifyComplete();
    }

    // -- THE takeover invariant ------------------------------------------------------------

    @Test
    void takeover_preferredUsernameEqualsVictimDiscordHandle_resolvesOwnCasdoor_neverDiscordVictim() {
        AdminBffInternalClient adminBff = mock(AdminBffInternalClient.class);
        // The victim's discord invite account under the SAME handle -- stubbed to catch a leak.
        when(adminBff.getAccount("discord:victim")).thenReturn(Mono.just(view("discord:victim", "victimlp", "victimlp")));
        // The caller's OWN account.
        when(adminBff.getAccount("casdoor:victim")).thenReturn(Mono.just(view("casdoor:victim", "callerlp", "callerlp")));
        CanonicalIdentityResolver r = new CanonicalIdentityResolver(adminBff);
        Jwt j = jwt("casdoor-uuid", Map.of("preferred_username", "victim"));

        StepVerifier.create(r.matrixLocalpart(j)).expectNext("callerlp").verifyComplete();

        verify(adminBff).getAccount("casdoor:victim");
        verify(adminBff, never()).getAccount("discord:victim");
    }

    // -- fail-closed (mint terminals) ------------------------------------------------------

    @Test
    void miss_noAccount_matrixAndMastodonFailClosed_401() {
        AdminBffInternalClient adminBff = mock(AdminBffInternalClient.class);
        when(adminBff.getAccount(anyString())).thenReturn(Mono.error(notFound()));
        CanonicalIdentityResolver r = new CanonicalIdentityResolver(adminBff);
        Jwt j = jwt("casdoor-uuid", Map.of("preferred_username", "nobody"));

        StepVerifier.create(r.matrixLocalpart(j))
                .expectErrorSatisfies(e -> assertThat(((ResponseStatusException) e).getStatusCode())
                        .isEqualTo(HttpStatus.UNAUTHORIZED))
                .verify();
        StepVerifier.create(r.mastodonLocalpart(j))
                .expectErrorSatisfies(e -> assertThat(((ResponseStatusException) e).getStatusCode())
                        .isEqualTo(HttpStatus.UNAUTHORIZED))
                .verify();
    }

    @Test
    void noIdentityClaimAtAll_failsClosed_401() {
        AdminBffInternalClient adminBff = mock(AdminBffInternalClient.class);
        CanonicalIdentityResolver r = new CanonicalIdentityResolver(adminBff);
        // No sub either -> subjectOf null -> 401 without any admin-bff hop.
        Jwt j = Jwt.withTokenValue("t").header("alg", "none")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(3600))
                .claim("roles", List.of("user")).build();

        StepVerifier.create(r.matrixLocalpart(j))
                .expectErrorSatisfies(e -> assertThat(((ResponseStatusException) e).getStatusCode())
                        .isEqualTo(HttpStatus.UNAUTHORIZED))
                .verify();
        verify(adminBff, never()).getAccount(anyString());
    }

    @Test
    void accountWithBlankLocalpart_failsClosed_409() {
        AdminBffInternalClient adminBff = mock(AdminBffInternalClient.class);
        when(adminBff.getAccount("casdoor:alice")).thenReturn(Mono.just(view("casdoor:alice", "", "")));
        CanonicalIdentityResolver r = new CanonicalIdentityResolver(adminBff);
        Jwt j = jwt("casdoor-uuid", Map.of("preferred_username", "alice"));

        StepVerifier.create(r.matrixLocalpart(j))
                .expectErrorSatisfies(e -> assertThat(((ResponseStatusException) e).getStatusCode())
                        .isEqualTo(HttpStatus.CONFLICT))
                .verify();
    }

    @Test
    void mastodon_blankPersistedFold_transitionallyFoldsPersistedMatrixLocalpart() {
        AdminBffInternalClient adminBff = mock(AdminBffInternalClient.class);
        // Matrix "john.doe" folds to Mastodon charset "john_doe"; persisted Mastodon fold blank.
        when(adminBff.getAccount("casdoor:john")).thenReturn(Mono.just(view("casdoor:john", "john.doe", "")));
        CanonicalIdentityResolver r = new CanonicalIdentityResolver(adminBff);
        Jwt j = jwt("casdoor-uuid", Map.of("preferred_username", "john"));

        StepVerifier.create(r.mastodonLocalpart(j)).expectNext("john_doe").verifyComplete();
    }

    // -- best-effort (self-silence terminals) ----------------------------------------------

    @Test
    void bestEffort_missDegradesToBlank_neverErrors() {
        AdminBffInternalClient adminBff = mock(AdminBffInternalClient.class);
        when(adminBff.getAccount(anyString())).thenReturn(Mono.error(notFound()));
        CanonicalIdentityResolver r = new CanonicalIdentityResolver(adminBff);
        Jwt j = jwt("casdoor-uuid", Map.of("preferred_username", "nobody"));

        StepVerifier.create(r.matrixLocalpartOrBlank(j)).expectNext("").verifyComplete();
        StepVerifier.create(r.mastodonLocalpartOrBlank(j)).expectNext("").verifyComplete();
    }

    @Test
    void bestEffort_claimPresentStillUsed() {
        AdminBffInternalClient adminBff = mock(AdminBffInternalClient.class);
        CanonicalIdentityResolver r = new CanonicalIdentityResolver(adminBff);
        Jwt j = jwt("casdoor:uuid", Map.of("localpart", "mx", "mastodon_localpart", "md"));
        StepVerifier.create(r.matrixLocalpartOrBlank(j)).expectNext("mx").verifyComplete();
        StepVerifier.create(r.mastodonLocalpartOrBlank(j)).expectNext("md").verifyComplete();
        verify(adminBff, never()).getAccount(anyString());
    }

    // -- subject-only (sticker leg) --------------------------------------------------------

    @Test
    void subjectMethod_fullAccountIdUsedVerbatim_bareSubjectNormalisedToCasdoor() {
        AdminBffInternalClient adminBff = mock(AdminBffInternalClient.class);
        when(adminBff.getAccount("casdoor:alice-sub")).thenReturn(Mono.just(view("casdoor:alice-sub", "alice", "")));
        when(adminBff.getAccount("google:al@x.com")).thenReturn(Mono.just(view("google:al@x.com", "algoog", "")));
        CanonicalIdentityResolver r = new CanonicalIdentityResolver(adminBff);

        // bare subject -> casdoor:<subject>
        StepVerifier.create(r.ownMatrixLocalpartForSubject("alice-sub")).expectNext("alice").verifyComplete();
        // full account id (contains ':') -> verbatim
        StepVerifier.create(r.ownMatrixLocalpartForSubject("google:al@x.com")).expectNext("algoog").verifyComplete();
    }

    @Test
    void subjectMethod_missOrBlankOrError_completesEmpty_noRawDerivation() {
        AdminBffInternalClient adminBff = mock(AdminBffInternalClient.class);
        when(adminBff.getAccount("casdoor:x")).thenReturn(Mono.error(notFound()));
        when(adminBff.getAccount("casdoor:blank")).thenReturn(Mono.just(view("casdoor:blank", "", "")));
        CanonicalIdentityResolver r = new CanonicalIdentityResolver(adminBff);

        StepVerifier.create(r.ownMatrixLocalpartForSubject("x")).verifyComplete();       // error -> empty
        StepVerifier.create(r.ownMatrixLocalpartForSubject("blank")).verifyComplete();   // blank -> empty
        StepVerifier.create(r.ownMatrixLocalpartForSubject("  ")).verifyComplete();      // blank subject -> empty
        StepVerifier.create(r.ownMatrixLocalpartForSubject(null)).verifyComplete();      // null -> empty
    }

    // -- idFor mirrors AccountStore.idFor --------------------------------------------------

    @Test
    void idFor_lowercasesAndTrims() {
        assertThat(CanonicalIdentityResolver.idFor("casdoor", "  Alice@X.com ")).isEqualTo("casdoor:alice@x.com");
        assertThat(CanonicalIdentityResolver.idFor("casdoor", "UUID-123")).isEqualTo("casdoor:uuid-123");
    }
}
