package systems.hugmesh.userbff.session;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import systems.hugmesh.commons.web.ApiException;
import systems.hugmesh.userbff.session.SessionsInternalClient.BffSessionWire;

import java.time.Instant;
import java.time.LocalDateTime;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link SessionsService} — the server-side account-derivation + ownership
 * logic that is the load-bearing cross-user-isolation guarantee, driven directly (no web
 * layer) with a Mockito {@link SessionsInternalClient}.
 */
class SessionsServiceTest {

    private static final LocalDateTime NOW = LocalDateTime.of(2026, 6, 23, 12, 0);
    private static final LocalDateTime LATER = NOW.plusHours(12);

    private static Jwt jwt(java.util.Map<String, Object> claims) {
        Jwt.Builder b = Jwt.withTokenValue("t").header("alg", "none");
        claims.forEach(b::claim);
        // A JWT must carry at least one claim besides the header; subject is harmless here.
        b.claim("sub", "subject");
        b.issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(3600));
        return b.build();
    }

    /** A synthetic native-login principal exactly as BffSessionAuthenticationWebFilter builds
     *  it: token value prefixed with the marker, {@code sub} = the account id. */
    private static Jwt syntheticSessionJwt(String accountId, java.util.Map<String, Object> extraClaims) {
        Jwt.Builder b = Jwt.withTokenValue(
                        systems.hugmesh.userbff.config.BffSessionAuthenticationWebFilter.SYNTHETIC_TOKEN_MARKER + accountId)
                .header("typ", "bff-synthetic-principal")
                .subject(accountId);
        extraClaims.forEach(b::claim);
        b.issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(3600));
        return b.build();
    }

    // ── account derivation = the production AuthController.accountFromJwt mapping ──────────

    @Test
    void accountIdFromJwt_realJwt_email_mapsToOwnCasdoorLowercased() {
        // Own-account key, mirroring admin-bff (subject=email, casdoor:<lc>) -- NOT the old google: guess.
        Jwt jwt = jwt(java.util.Map.of("email", "Alice@Example.COM"));
        assertThat(SessionsService.accountIdFromJwt(jwt)).isEqualTo("casdoor:alice@example.com");
    }

    @Test
    void accountIdFromJwt_realJwt_preferredUsername_mapsToOwnCasdoorLowercased_whenNoEmail() {
        // subject precedence email>preferred_username>sub; no email -> casdoor:<pu-lc>, never discord:.
        Jwt jwt = jwt(java.util.Map.of("preferred_username", "ZeD"));
        assertThat(SessionsService.accountIdFromJwt(jwt)).isEqualTo("casdoor:zed");
    }

    @Test
    void accountIdFromJwt_realJwt_emailWins_overPreferredUsername() {
        Jwt jwt = jwt(java.util.Map.of("email", "alice@example.com", "preferred_username", "alice"));
        assertThat(SessionsService.accountIdFromJwt(jwt)).isEqualTo("casdoor:alice@example.com");
    }

    @Test
    void accountIdFromJwt_realJwt_onlySub_resolvesOwnCasdoorBySub() {
        // sub is the LAST subject-precedence source (mirroring admin-bff's SUBJECT_CLAIMS) -- a real
        // Casdoor JWT with only sub resolves casdoor:<sub>, its OWN account (an improvement over the
        // old code, which failed closed when email+preferred_username were both absent).
        Jwt jwt = jwt(java.util.Map.of("name", "nobody")); // jwt() helper also sets sub="subject"
        assertThat(SessionsService.accountIdFromJwt(jwt)).isEqualTo("casdoor:subject");
    }

    @Test
    void accountIdFromJwt_realJwt_noSubjectClaimAtAll_isUnauthorized() {
        // A token carrying NO email/preferred_username/sub -> no derivable own account -> 401.
        Jwt jwt = Jwt.withTokenValue("t").header("alg", "none")
                .claim("name", "nobody")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(3600))
                .build();
        assertThatThrownBy(() -> SessionsService.accountIdFromJwt(jwt))
                .isInstanceOf(ApiException.class);
    }

    @Test
    void accountIdFromJwt_realJwt_preferredUsernameCollidesWithVictimDiscord_resolvesOwnCasdoor_neverVictim() {
        // THE takeover regression: a real Casdoor JWT with preferred_username == an existing
        // discord: invite account's handle MUST resolve the caller's OWN casdoor:<handle> account
        // id, never the victim's discord:<handle>.
        Jwt jwt = jwt(java.util.Map.of("preferred_username", "victim"));
        assertThat(SessionsService.accountIdFromJwt(jwt)).isEqualTo("casdoor:victim");
    }

    // ── native-login synthetic principal: sub IS the account id (the casdoor gap fix) ─────

    @Test
    void accountIdFromJwt_syntheticSessionPrincipal_usesSubjectVerbatim() {
        // The exact id admin-bff stores in bff_session.account_id for a native-login casdoor
        // account — must be used as-is, NOT re-derived to a wrong discord:/google: id.
        Jwt jwt = syntheticSessionJwt("casdoor:14d1072e-f2e0-438e-a3cc-6a8579f36c5a", java.util.Map.of());
        assertThat(SessionsService.accountIdFromJwt(jwt))
                .isEqualTo("casdoor:14d1072e-f2e0-438e-a3cc-6a8579f36c5a");
    }

    @Test
    void accountIdFromJwt_syntheticPrincipal_subjectWins_overPreferredUsername() {
        // #108's synthetic Jwt ALSO sets preferred_username=handle; the marker path must take
        // precedence so a native-login account is never mis-mapped to discord:<handle> (the
        // exact bug that made /bff/user/sessions return an empty list live).
        Jwt jwt = syntheticSessionJwt("casdoor:abc", java.util.Map.of("preferred_username", "somehandle"));
        assertThat(SessionsService.accountIdFromJwt(jwt)).isEqualTo("casdoor:abc");
    }

    @Test
    void accountIdFromJwt_syntheticPrincipal_googleProvider_usesSubjectNotEmailDerivation() {
        // Even for a google-provider synthetic principal (email claim present), the stored
        // account id is sub verbatim — the marker path must not fall through to google: derivation
        // (which would only coincidentally match, and only when handle==email-localpart).
        Jwt jwt = syntheticSessionJwt("google:alice@example.com",
                java.util.Map.of("email", "alice@example.com"));
        assertThat(SessionsService.accountIdFromJwt(jwt)).isEqualTo("google:alice@example.com");
    }

    @Test
    void accountIdFromJwt_syntheticPrincipal_blankSubject_isUnauthorized_notFallthrough() {
        Jwt jwt = Jwt.withTokenValue(
                        systems.hugmesh.userbff.config.BffSessionAuthenticationWebFilter.SYNTHETIC_TOKEN_MARKER)
                .header("typ", "bff-synthetic-principal")
                .claim("preferred_username", "wouldbe-discord")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(3600))
                .build();
        assertThatThrownBy(() -> SessionsService.accountIdFromJwt(jwt))
                .isInstanceOf(ApiException.class);
    }

    // ── fingerprint = opaque, deterministic, not the raw token ────────────────────────────

    @Test
    void fingerprint_isDeterministic_andNotTheRawToken() {
        String fp1 = SessionsService.fingerprint("bff_secret");
        String fp2 = SessionsService.fingerprint("bff_secret");
        assertThat(fp1).isEqualTo(fp2);
        assertThat(fp1).isNotEqualTo("bff_secret");
        assertThat(fp1).hasSize(64); // SHA-256 hex
        assertThat(SessionsService.fingerprint("bff_other")).isNotEqualTo(fp1);
    }

    // ── list / revoke delegate with the server-derived account ────────────────────────────

    @Test
    void listMine_usesJwtDerivedAccount_andProjectsToOpaqueId() {
        SessionsInternalClient internal = mock(SessionsInternalClient.class);
        when(internal.sessionsForAccount(eq("casdoor:alice@example.com")))
                .thenReturn(Flux.just(new BffSessionWire("bff_tokA", "casdoor:alice@example.com", NOW, LATER)));
        SessionsService svc = new SessionsService(internal);

        StepVerifier.create(svc.listMine(jwt(java.util.Map.of("email", "alice@example.com"))))
                .assertNext(s -> {
                    assertThat(s.id()).isEqualTo(SessionsService.fingerprint("bff_tokA"));
                    assertThat(s.createdAt()).isEqualTo(NOW);
                })
                .verifyComplete();
        verify(internal).sessionsForAccount("casdoor:alice@example.com");
    }

    @Test
    void listMine_realJwt_preferredUsernameCollidesWithVictimDiscord_listsOwnCasdoor_neverVictimDiscordSessions() {
        // THE takeover regression at the SERVICE boundary: a real Casdoor JWT whose
        // preferred_username equals an existing discord: invite account's handle must list the
        // caller's OWN casdoor:<handle> sessions and NEVER query admin-bff for the victim's
        // discord:<handle> sessions (which the old guess would have listed/revoked).
        SessionsInternalClient internal = mock(SessionsInternalClient.class);
        when(internal.sessionsForAccount(eq("casdoor:victim")))
                .thenReturn(Flux.just(new BffSessionWire("bff_caller", "casdoor:victim", NOW, LATER)));
        // The victim's sessions -- stubbed to catch a leak; must never be requested.
        when(internal.sessionsForAccount(eq("discord:victim")))
                .thenReturn(Flux.just(new BffSessionWire("bff_victim", "discord:victim", NOW, LATER)));
        SessionsService svc = new SessionsService(internal);

        StepVerifier.create(svc.listMine(jwt(java.util.Map.of("preferred_username", "victim"))))
                .assertNext(session -> assertThat(session.id())
                        .isEqualTo(SessionsService.fingerprint("bff_caller")))
                .verifyComplete();

        verify(internal).sessionsForAccount("casdoor:victim");
        verify(internal, never()).sessionsForAccount("discord:victim");
    }

    @Test
    void revokeMine_ownSession_deletesResolvedRawToken() {
        SessionsInternalClient internal = mock(SessionsInternalClient.class);
        when(internal.sessionsForAccount(eq("casdoor:alice@example.com")))
                .thenReturn(Flux.just(new BffSessionWire("bff_tokA", "casdoor:alice@example.com", NOW, LATER)));
        when(internal.deleteSession(eq("bff_tokA"))).thenReturn(Mono.empty());
        SessionsService svc = new SessionsService(internal);

        StepVerifier.create(svc.revokeMine(jwt(java.util.Map.of("email", "alice@example.com")),
                        SessionsService.fingerprint("bff_tokA")))
                .verifyComplete();
        verify(internal).deleteSession("bff_tokA");
    }

    @Test
    void revokeMine_foreignId_isNotFound_andNeverDeletes() {
        SessionsInternalClient internal = mock(SessionsInternalClient.class);
        when(internal.sessionsForAccount(eq("casdoor:alice@example.com")))
                .thenReturn(Flux.just(new BffSessionWire("bff_tokA", "casdoor:alice@example.com", NOW, LATER)));
        SessionsService svc = new SessionsService(internal);

        StepVerifier.create(svc.revokeMine(jwt(java.util.Map.of("email", "alice@example.com")),
                        SessionsService.fingerprint("bff_someoneElse")))
                .verifyError(ApiException.class);
        verify(internal, never()).deleteSession(org.mockito.ArgumentMatchers.anyString());
    }

    // ── graceful degradation: an unwired client yields empty list / no-op revoke ──────────

    @Test
    void unwiredClient_listIsEmpty_revokeIsNotFound() {
        SessionsInternalClient stub = new SessionsInternalClient(null);
        assertThat(stub.enabled()).isFalse();
        SessionsService svc = new SessionsService(stub);

        StepVerifier.create(svc.listMine(jwt(java.util.Map.of("email", "alice@example.com"))))
                .verifyComplete(); // empty
        // With no sessions to match, ANY id 404s (anti-enumeration) and never deletes.
        StepVerifier.create(svc.revokeMine(jwt(java.util.Map.of("email", "alice@example.com")), "anyid"))
                .verifyError(ApiException.class);
    }
}
