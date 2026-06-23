package systems.snapdragon.userbff.session;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import systems.snapdragon.commons.web.ApiException;
import systems.snapdragon.userbff.session.SessionsInternalClient.BffSessionWire;

import java.time.Instant;
import java.time.LocalDateTime;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
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

    // ── account derivation = the production AuthController.accountFromJwt mapping ──────────

    @Test
    void accountIdFromJwt_email_mapsToGoogleLowercased() {
        Jwt jwt = jwt(java.util.Map.of("email", "Alice@Example.COM"));
        assertThat(SessionsService.accountIdFromJwt(jwt)).isEqualTo("google:alice@example.com");
    }

    @Test
    void accountIdFromJwt_preferredUsername_mapsToDiscordLowercased_whenNoEmail() {
        Jwt jwt = jwt(java.util.Map.of("preferred_username", "ZeD"));
        assertThat(SessionsService.accountIdFromJwt(jwt)).isEqualTo("discord:zed");
    }

    @Test
    void accountIdFromJwt_emailWins_overPreferredUsername() {
        Jwt jwt = jwt(java.util.Map.of("email", "alice@example.com", "preferred_username", "alice"));
        assertThat(SessionsService.accountIdFromJwt(jwt)).isEqualTo("google:alice@example.com");
    }

    @Test
    void accountIdFromJwt_neitherClaim_isUnauthorized() {
        Jwt jwt = jwt(java.util.Map.of("name", "nobody"));
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
        when(internal.sessionsForAccount(eq("google:alice@example.com")))
                .thenReturn(Flux.just(new BffSessionWire("bff_tokA", "google:alice@example.com", NOW, LATER)));
        SessionsService svc = new SessionsService(internal);

        StepVerifier.create(svc.listMine(jwt(java.util.Map.of("email", "alice@example.com"))))
                .assertNext(s -> {
                    assertThat(s.id()).isEqualTo(SessionsService.fingerprint("bff_tokA"));
                    assertThat(s.createdAt()).isEqualTo(NOW);
                })
                .verifyComplete();
        verify(internal).sessionsForAccount("google:alice@example.com");
    }

    @Test
    void revokeMine_ownSession_deletesResolvedRawToken() {
        SessionsInternalClient internal = mock(SessionsInternalClient.class);
        when(internal.sessionsForAccount(eq("google:alice@example.com")))
                .thenReturn(Flux.just(new BffSessionWire("bff_tokA", "google:alice@example.com", NOW, LATER)));
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
        when(internal.sessionsForAccount(eq("google:alice@example.com")))
                .thenReturn(Flux.just(new BffSessionWire("bff_tokA", "google:alice@example.com", NOW, LATER)));
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
