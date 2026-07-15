package systems.snapdragon.userbff.silence;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import systems.snapdragon.userbff.auth.AdminBffInternalClient;
import systems.snapdragon.userbff.security.PrincipalDomain;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Self-silence identity-canonicalisation close — the companion to {@code
 * HsProxyLocalpartFallbackTest}'s plain-object style, for the two homeserver hide seams
 * instead of the two D6 proxy mint sites. {@link SelfSilenceController}'s activate/cancel
 * used to derive the hide-seam localpart from the raw JWT {@code preferred_username}
 * claim — the SAME class of account-takeover-by-collision bug {@code
 * MatrixProxyController}/{@code MastodonProxyController} already closed for the
 * homeserver-MINT call sites: two DIFFERENT admin-bff accounts CAN share a {@code
 * preferred_username} (it is not admin-bff's uniqueness key), so the old derivation could
 * hide/un-hide the WRONG account's directory entry.
 *
 * <p>Drives the controller's public {@code activate}/{@code cancel} entry points directly
 * (no Spring context) with a mocked {@link SelfSilenceService} + {@link
 * AdminBffInternalClient} + {@link PrincipalDomain}.
 */
class SelfSilenceControllerLocalpartFallbackTest {

    private static Jwt jwtWithClaims(String subject, Map<String, Object> claims) {
        Jwt.Builder b = Jwt.withTokenValue("real-casdoor-jwt")
                .header("alg", "none")
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(3600))
                .subject(subject);
        claims.forEach(b::claim);
        return b.build();
    }

    private static SelfSilenceController.ActivateRequest activateBody() {
        return new SelfSilenceController.ActivateRequest(Instant.now().plusSeconds(3600), null);
    }

    private static SelfSilence rowFor(String owner) {
        return new SelfSilence(owner, Instant.now(), Instant.now().plusSeconds(3600), null, null, Instant.now());
    }

    @Test
    void activate_syntheticLocalpartClaims_usedDirectly_adminBffNeverCalled() {
        // The PRIMARY (native-login / bff_-session) path: the claims BffSessionAuthentication
        // WebFilter.syntheticJwt stamps are used as-is — no admin-bff hop at all.
        SelfSilenceService silence = mock(SelfSilenceService.class);
        AdminBffInternalClient adminBff = mock(AdminBffInternalClient.class);
        PrincipalDomain principalDomain = mock(PrincipalDomain.class);
        when(principalDomain.forScope(any())).thenReturn("default");
        when(silence.activate(eq("casdoor:uuid"), eq("mx-lp"), eq("md-lp"), any(), any(), eq("default")))
                .thenReturn(Mono.just(rowFor("casdoor:uuid")));

        SelfSilenceController controller = new SelfSilenceController(silence, principalDomain, adminBff);
        Jwt jwt = jwtWithClaims("casdoor:uuid", Map.of(
                "localpart", "mx-lp", "mastodon_localpart", "md-lp", "preferred_username", "ignored"));

        StepVerifier.create(controller.activate(jwt, activateBody())).expectNextCount(1).verifyComplete();

        verify(silence).activate(eq("casdoor:uuid"), eq("mx-lp"), eq("md-lp"), any(), any(), eq("default"));
        verify(adminBff, never()).getAccount(anyString());
    }

    @Test
    void activate_realJwt_noClaims_resolvesCanonicalValueViaAdminBff_notRawClaim() {
        SelfSilenceService silence = mock(SelfSilenceService.class);
        AdminBffInternalClient adminBff = mock(AdminBffInternalClient.class);
        PrincipalDomain principalDomain = mock(PrincipalDomain.class);
        when(principalDomain.forScope(any())).thenReturn("default");
        when(adminBff.getAccount("google:alice@x.com")).thenReturn(Mono.just(
                new AdminBffInternalClient.AccountView("google:alice@x.com", "google", "alice@x.com",
                        true, List.of("user"), "alice-mx", "alice_md")));
        when(silence.activate(eq("casdoor-subject"), eq("alice-mx"), eq("alice_md"), any(), any(), eq("default")))
                .thenReturn(Mono.just(rowFor("casdoor-subject")));

        SelfSilenceController controller = new SelfSilenceController(silence, principalDomain, adminBff);
        Jwt jwt = jwtWithClaims("casdoor-subject", Map.of("email", "alice@x.com"));

        StepVerifier.create(controller.activate(jwt, activateBody())).expectNextCount(1).verifyComplete();

        verify(silence).activate(eq("casdoor-subject"), eq("alice-mx"), eq("alice_md"), any(), any(), eq("default"));
        // The OLD (pre-fix) behaviour would have hidden under the raw preferred_username/sub —
        // must never happen once admin-bff resolves a canonical value.
        verify(silence, never()).activate(anyString(), eq("alice@x.com"), anyString(), any(), any(), anyString());
    }

    @Test
    void activate_twoAccountsShareSamePreferredUsername_resolveToDistinctLocalparts_noCollision() {
        // The exact collision vector the old preferred_username-derivation was vulnerable
        // to: two DIFFERENT admin-bff accounts sharing "alice" as preferred_username, but
        // registered under different emails, MUST resolve to their OWN distinct canonical
        // Matrix localpart — never collide on the same directory-hide target.
        SelfSilenceService silence = mock(SelfSilenceService.class);
        AdminBffInternalClient adminBff = mock(AdminBffInternalClient.class);
        PrincipalDomain principalDomain = mock(PrincipalDomain.class);
        when(principalDomain.forScope(any())).thenReturn("default");
        when(silence.activate(anyString(), anyString(), anyString(), any(), any(), anyString()))
                .thenAnswer(inv -> Mono.just(rowFor(inv.getArgument(0))));
        when(adminBff.getAccount("google:alice@x.com")).thenReturn(Mono.just(
                new AdminBffInternalClient.AccountView("google:alice@x.com", "google", "alice@x.com",
                        true, List.of("user"), "alice-account-a", "alice-account-a")));
        when(adminBff.getAccount("google:alice@y.com")).thenReturn(Mono.just(
                new AdminBffInternalClient.AccountView("google:alice@y.com", "google", "alice@y.com",
                        true, List.of("user"), "alice-account-b", "alice-account-b")));
        // resolveAccountView builds the discord-derived candidate Mono EAGERLY too (a real
        // WebClient call is lazy until subscribed; a Mockito stub invocation is not) — it is
        // never actually used here since byEmail always resolves first, but must be stubbed
        // to avoid an NPE on construction.
        when(adminBff.getAccount("discord:alice")).thenReturn(Mono.empty());

        SelfSilenceController controller = new SelfSilenceController(silence, principalDomain, adminBff);
        Jwt jwtA = jwtWithClaims("casdoor-a", Map.of("email", "alice@x.com", "preferred_username", "alice"));
        Jwt jwtB = jwtWithClaims("casdoor-b", Map.of("email", "alice@y.com", "preferred_username", "alice"));

        controller.activate(jwtA, activateBody()).block();
        controller.activate(jwtB, activateBody()).block();

        verify(silence).activate(eq("casdoor-a"), eq("alice-account-a"), eq("alice-account-a"),
                any(), any(), eq("default"));
        verify(silence).activate(eq("casdoor-b"), eq("alice-account-b"), eq("alice-account-b"),
                any(), any(), eq("default"));
    }

    @Test
    void activate_unresolvableIdentity_degradesToBlank_neverFailsTheCallersOwnRequest() {
        // UNLIKE the homeserver-MINT call sites (MatrixProxyController et al.), a self-
        // silence hide is best-effort + gated: an unresolved identity must NOT fail the
        // caller's own activate — it degrades to "" and SelfSilenceService skips that leg.
        SelfSilenceService silence = mock(SelfSilenceService.class);
        AdminBffInternalClient adminBff = mock(AdminBffInternalClient.class);
        PrincipalDomain principalDomain = mock(PrincipalDomain.class);
        when(principalDomain.forScope(any())).thenReturn("default");
        when(adminBff.getAccount(anyString())).thenReturn(Mono.error(
                WebClientResponseException.create(404, "Not Found", HttpHeaders.EMPTY, new byte[0], null)));
        when(silence.activate(eq("mallory"), eq(""), eq(""), any(), any(), eq("default")))
                .thenReturn(Mono.just(rowFor("mallory")));

        SelfSilenceController controller = new SelfSilenceController(silence, principalDomain, adminBff);
        Jwt jwt = jwtWithClaims("mallory", Map.of("preferred_username", "mallory"));

        StepVerifier.create(controller.activate(jwt, activateBody())).expectNextCount(1).verifyComplete();

        verify(silence).activate(eq("mallory"), eq(""), eq(""), any(), any(), eq("default"));
    }

    @Test
    void cancel_syntheticLocalpartClaims_usedDirectly() {
        SelfSilenceService silence = mock(SelfSilenceService.class);
        AdminBffInternalClient adminBff = mock(AdminBffInternalClient.class);
        PrincipalDomain principalDomain = mock(PrincipalDomain.class);
        when(principalDomain.forScope(any())).thenReturn("default");
        when(silence.cancel(eq("casdoor:uuid"), eq("mx-lp"), eq("md-lp"), eq("default")))
                .thenReturn(Mono.empty());

        SelfSilenceController controller = new SelfSilenceController(silence, principalDomain, adminBff);
        Jwt jwt = jwtWithClaims("casdoor:uuid", Map.of("localpart", "mx-lp", "mastodon_localpart", "md-lp"));

        StepVerifier.create(controller.cancel(jwt)).expectNextCount(1).verifyComplete();

        verify(silence).cancel(eq("casdoor:uuid"), eq("mx-lp"), eq("md-lp"), eq("default"));
        verify(adminBff, never()).getAccount(anyString());
    }
}
