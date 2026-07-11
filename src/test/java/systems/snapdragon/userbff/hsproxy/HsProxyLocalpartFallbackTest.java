package systems.snapdragon.userbff.hsproxy;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import systems.snapdragon.userbff.auth.AdminBffInternalClient;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Gap-1 close (adversarial round-1-review finding, CRITICAL): {@code
 * MatrixProxyController}/{@code MastodonProxyController}'s private {@code localpart(Jwt)}
 * helper has a FALLBACK branch — used whenever the synthetic-session {@code localpart}
 * claim is absent — that is reachable by any caller presenting a REAL, externally-issued,
 * validly-signed Casdoor JWT directly to these routes ({@code SecurityConfig} still fully
 * wires {@code o.jwt(...)} against the live issuer-uri here; only an opaque {@code bff_}
 * session ever passes through {@code BffSessionAuthenticationWebFilter} and picks up the
 * synthetic claim). Round 1 left that branch re-deriving an UNCHECKED candidate from
 * {@code preferred_username}/{@code sub} — exactly the account-takeover-by-collision bug
 * this whole fix exists to close.
 *
 * <p>This test drives the controllers' PUBLIC {@code proxy(Jwt, ServerWebExchange)} entry
 * point directly (no Spring context — a plain object test, same idiom as {@link
 * HsReverseProxyLazyMintTest}) with custody forced empty so the mint leg — and therefore
 * {@code localpart(jwt)} — is actually subscribed, and asserts:
 * <ul>
 *   <li>a real JWT with no {@code localpart} claim resolves the account via a genuine
 *       {@link AdminBffInternalClient#getAccount} call (the SAME (provider,handle) → id
 *       derivation admin-bff's own mint site uses) and mints with the PERSISTED value —
 *       never with the raw claim itself;</li>
 *   <li>an unresolvable identity (lookup 404s / no account) FAILS CLOSED — the broker's
 *       mint is NEVER invoked, so no homeserver token is ever brokered off an unchecked
 *       candidate.</li>
 * </ul>
 */
class HsProxyLocalpartFallbackTest {

    private static Jwt jwtWithClaims(String subject, java.util.Map<String, Object> claims) {
        Jwt.Builder b = Jwt.withTokenValue("real-casdoor-jwt")
                .header("alg", "none")
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(3600))
                .subject(subject);
        claims.forEach(b::claim);
        return b.build();
    }

    private static ServerWebExchange exchangeFor(String path) {
        return MockServerWebExchange.from(MockServerHttpRequest.get(path).build());
    }

    // ──────────────────────────── Matrix ────────────────────────────

    @Test
    void matrix_realJwt_noLocalpartClaim_resolvesCanonicalValueViaAdminBff_notRawClaim() {
        HsTokenCustody custody = mock(HsTokenCustody.class);
        ServiceTokenBroker broker = mock(ServiceTokenBroker.class);
        AdminBffInternalClient adminBff = mock(AdminBffInternalClient.class);
        when(custody.cipherAvailable()).thenReturn(true);
        when(custody.loadAccessToken(anyString(), anyString())).thenReturn(Mono.empty());
        when(adminBff.getAccount("google:alice@x.com")).thenReturn(Mono.just(
                new AdminBffInternalClient.AccountView("google:alice@x.com", "google", "alice@x.com",
                        true, List.of("user"), "aliceonhs")));
        when(broker.mintMatrix(anyString(), eq("aliceonhs")))
                .thenReturn(Mono.just(new MintedToken("native-tok", null, null, "aliceonhs")));

        MatrixProxyController controller = new MatrixProxyController(true, custody, broker,
                WebClient.builder().baseUrl("http://127.0.0.1:1").build(), adminBff);
        Jwt jwt = jwtWithClaims("casdoor-subject", java.util.Map.of("email", "alice@x.com"));

        // The downstream HTTP forward to the stub upstream inevitably errors (nothing is
        // listening) — swallow it; only the interaction BEFORE that (mint resolution) is
        // under test here, exactly like HsReverseProxyLazyMintTest's shape.
        controller.proxy(jwt, exchangeFor("/bff/user/matrix/_matrix/client/v3/sync"))
                .onErrorResume(e -> Mono.empty())
                .block(Duration.ofSeconds(10));

        verify(adminBff).getAccount("google:alice@x.com");
        verify(broker).mintMatrix(anyString(), eq("aliceonhs"));
        // The OLD (pre-fix) behaviour would have minted with the raw claim value directly —
        // must never happen now.
        verify(broker, never()).mintMatrix(anyString(), eq("alice@x.com"));
    }

    @Test
    void matrix_realJwt_noResolvableAccount_failsClosed_neverMints() {
        HsTokenCustody custody = mock(HsTokenCustody.class);
        ServiceTokenBroker broker = mock(ServiceTokenBroker.class);
        AdminBffInternalClient adminBff = mock(AdminBffInternalClient.class);
        when(custody.cipherAvailable()).thenReturn(true);
        when(custody.loadAccessToken(anyString(), anyString())).thenReturn(Mono.empty());
        // Neither the google- nor discord-derived id resolves an account (404 both times) —
        // the fail-closed path, NOT a fall back to the old preferred_username derivation.
        when(adminBff.getAccount(anyString())).thenReturn(Mono.error(
                WebClientResponseException.create(404, "Not Found", HttpHeaders.EMPTY, new byte[0], null)));

        MatrixProxyController controller = new MatrixProxyController(true, custody, broker,
                WebClient.builder().baseUrl("http://127.0.0.1:1").build(), adminBff);
        Jwt jwt = jwtWithClaims("casdoor-subject", java.util.Map.of("preferred_username", "mallory"));

        reactor.test.StepVerifier.create(
                        controller.proxy(jwt, exchangeFor("/bff/user/matrix/_matrix/client/v3/sync")))
                .expectErrorSatisfies(e -> assertThat(e).isInstanceOf(ResponseStatusException.class))
                .verify(Duration.ofSeconds(10));

        verify(broker, never()).mintMatrix(anyString(), anyString());
    }

    @Test
    void matrix_syntheticLocalpartClaim_usedDirectly_adminBffNeverCalled() {
        // The PRIMARY (round-1) path is unaffected: when the localpart claim IS present
        // (the native-login synthetic Jwt), it is used as-is — no admin-bff hop at all.
        HsTokenCustody custody = mock(HsTokenCustody.class);
        ServiceTokenBroker broker = mock(ServiceTokenBroker.class);
        AdminBffInternalClient adminBff = mock(AdminBffInternalClient.class);
        when(custody.cipherAvailable()).thenReturn(true);
        when(custody.loadAccessToken(anyString(), anyString())).thenReturn(Mono.empty());
        when(broker.mintMatrix(anyString(), eq("canonical-lp")))
                .thenReturn(Mono.just(new MintedToken("native-tok", null, null, "canonical-lp")));

        MatrixProxyController controller = new MatrixProxyController(true, custody, broker,
                WebClient.builder().baseUrl("http://127.0.0.1:1").build(), adminBff);
        Jwt jwt = jwtWithClaims("casdoor:uuid",
                java.util.Map.of("localpart", "canonical-lp", "preferred_username", "should-be-ignored"));

        controller.proxy(jwt, exchangeFor("/bff/user/matrix/_matrix/client/v3/sync"))
                .onErrorResume(e -> Mono.empty())
                .block(Duration.ofSeconds(10));

        verify(broker).mintMatrix(anyString(), eq("canonical-lp"));
        verify(adminBff, never()).getAccount(anyString());
    }

    // ──────────────────────────── Mastodon ────────────────────────────

    @Test
    void mastodon_realJwt_noLocalpartClaim_resolvesCanonicalValueViaAdminBff_notRawClaim() {
        HsTokenCustody custody = mock(HsTokenCustody.class);
        ServiceTokenBroker broker = mock(ServiceTokenBroker.class);
        AdminBffInternalClient adminBff = mock(AdminBffInternalClient.class);
        when(custody.cipherAvailable()).thenReturn(true);
        when(custody.loadAccessToken(anyString(), anyString())).thenReturn(Mono.empty());
        when(adminBff.getAccount("discord:bobby")).thenReturn(Mono.just(
                new AdminBffInternalClient.AccountView("discord:bobby", "discord", "bobby",
                        true, List.of("user"), "bobonhs")));
        when(broker.mintMastodon(anyString(), eq("bobonhs")))
                .thenReturn(Mono.just(new MintedToken("native-tok", null, null, "bobonhs")));

        MastodonProxyController controller = new MastodonProxyController(true, custody, broker,
                WebClient.builder().baseUrl("http://127.0.0.1:1").build(), adminBff);
        Jwt jwt = jwtWithClaims("casdoor-subject", java.util.Map.of("preferred_username", "bobby"));

        controller.proxy(jwt, exchangeFor("/bff/user/mastodon/api/v1/timelines/home"))
                .onErrorResume(e -> Mono.empty())
                .block(Duration.ofSeconds(10));

        verify(adminBff).getAccount("discord:bobby");
        verify(broker).mintMastodon(anyString(), eq("bobonhs"));
        verify(broker, never()).mintMastodon(anyString(), eq("bobby"));
    }

    @Test
    void mastodon_syntheticMastodonClaim_usedDirectly_adminBffNeverCalled() {
        // 291: the synthetic bff_ session Jwt carries the persisted mastodon_localpart claim —
        // used as-is for the mint (no admin-bff hop, no re-fold). The localpart claim (Matrix)
        // is present too and MUST be ignored for the Mastodon mint.
        HsTokenCustody custody = mock(HsTokenCustody.class);
        ServiceTokenBroker broker = mock(ServiceTokenBroker.class);
        AdminBffInternalClient adminBff = mock(AdminBffInternalClient.class);
        when(custody.cipherAvailable()).thenReturn(true);
        when(custody.loadAccessToken(anyString(), anyString())).thenReturn(Mono.empty());
        when(broker.mintMastodon(anyString(), eq("bob_ml")))
                .thenReturn(Mono.just(new MintedToken("native-tok", null, null, "bob_ml")));

        MastodonProxyController controller = new MastodonProxyController(true, custody, broker,
                WebClient.builder().baseUrl("http://127.0.0.1:1").build(), adminBff);
        Jwt jwt = jwtWithClaims("casdoor:uuid", java.util.Map.of(
                "mastodon_localpart", "bob_ml", "localpart", "bob.ml", "preferred_username", "ignored"));

        controller.proxy(jwt, exchangeFor("/bff/user/mastodon/api/v1/timelines/home"))
                .onErrorResume(e -> Mono.empty())
                .block(Duration.ofSeconds(10));

        verify(broker).mintMastodon(anyString(), eq("bob_ml"));
        verify(broker, never()).mintMastodon(anyString(), eq("bob.ml"));
        verify(adminBff, never()).getAccount(anyString());
    }

    @Test
    void mastodon_realJwt_readsPersistedMastodonFold_notARefoldOfMatrixLocalpart() {
        // 291 airtightness: the mint reads the PERSISTED Mastodon fold, never a re-fold of the
        // Matrix localpart. Matrix localpart "bob.hs" would re-fold to "bob_hs", but the persisted
        // (e.g. backfill-disambiguated) Mastodon value is "bob_disambig" — the mint MUST use the
        // persisted value, or a backfilled colliding row would still be takeover-reachable.
        HsTokenCustody custody = mock(HsTokenCustody.class);
        ServiceTokenBroker broker = mock(ServiceTokenBroker.class);
        AdminBffInternalClient adminBff = mock(AdminBffInternalClient.class);
        when(custody.cipherAvailable()).thenReturn(true);
        when(custody.loadAccessToken(anyString(), anyString())).thenReturn(Mono.empty());
        when(adminBff.getAccount("discord:bobby")).thenReturn(Mono.just(
                new AdminBffInternalClient.AccountView("discord:bobby", "discord", "bobby",
                        true, List.of("user"), "bob.hs", "bob_disambig")));
        when(broker.mintMastodon(anyString(), eq("bob_disambig")))
                .thenReturn(Mono.just(new MintedToken("native-tok", null, null, "bob_disambig")));

        MastodonProxyController controller = new MastodonProxyController(true, custody, broker,
                WebClient.builder().baseUrl("http://127.0.0.1:1").build(), adminBff);
        Jwt jwt = jwtWithClaims("casdoor-subject", java.util.Map.of("preferred_username", "bobby"));

        controller.proxy(jwt, exchangeFor("/bff/user/mastodon/api/v1/timelines/home"))
                .onErrorResume(e -> Mono.empty())
                .block(Duration.ofSeconds(10));

        verify(broker).mintMastodon(anyString(), eq("bob_disambig"));
        verify(broker, never()).mintMastodon(anyString(), eq("bob_hs"));
    }

    @Test
    void mastodon_realJwt_noClaimsAtAll_failsClosed_neverMints() {
        HsTokenCustody custody = mock(HsTokenCustody.class);
        ServiceTokenBroker broker = mock(ServiceTokenBroker.class);
        AdminBffInternalClient adminBff = mock(AdminBffInternalClient.class);
        when(custody.cipherAvailable()).thenReturn(true);
        when(custody.loadAccessToken(anyString(), anyString())).thenReturn(Mono.empty());

        MastodonProxyController controller = new MastodonProxyController(true, custody, broker,
                WebClient.builder().baseUrl("http://127.0.0.1:1").build(), adminBff);
        // Neither email nor preferred_username present — nothing to derive an id from at all.
        Jwt jwt = jwtWithClaims("casdoor-subject", java.util.Map.of());

        reactor.test.StepVerifier.create(
                        controller.proxy(jwt, exchangeFor("/bff/user/mastodon/api/v1/timelines/home")))
                .expectErrorSatisfies(e -> assertThat(e).isInstanceOf(ResponseStatusException.class))
                .verify(Duration.ofSeconds(10));

        verify(adminBff, never()).getAccount(anyString());
        verify(broker, never()).mintMastodon(anyString(), anyString());
    }
}
