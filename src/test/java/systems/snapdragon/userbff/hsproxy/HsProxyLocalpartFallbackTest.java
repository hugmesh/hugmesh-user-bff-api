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
import systems.snapdragon.userbff.auth.CanonicalIdentityResolver;

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
 * Account-takeover-by-collision close for the two D6 proxy MINT sites, now via the shared
 * {@link CanonicalIdentityResolver}. {@code MatrixProxyController}/{@code MastodonProxyController}
 * used to derive the re-mint localpart, whenever the synthetic-session {@code localpart} claim is
 * absent, from a RAW cross-namespace guess ({@code email -> google:<email>} else
 * {@code preferred_username -> discord:<pu>}) -- reachable by any caller presenting a REAL,
 * externally-issued, validly-signed Casdoor JWT directly to these routes. That guess could resolve
 * a DIFFERENT person's invite account and mint a homeserver token under the VICTIM's persisted
 * localpart: cross-user account takeover.
 *
 * <p>The fix resolves the caller's OWN {@code casdoor:<subject>} account (subject = first non-blank
 * of {@code email}/{@code preferred_username}/{@code sub}), mints under its PERSISTED localpart, and
 * FAILS CLOSED on any miss -- it can NEVER resolve a foreign provider-namespace account. This test
 * drives the controllers' PUBLIC {@code proxy(Jwt, ServerWebExchange)} entry point directly (no
 * Spring context) with custody forced empty so the mint leg -- and therefore the resolver -- is
 * actually subscribed.
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

    private static CanonicalIdentityResolver resolver(AdminBffInternalClient adminBff) {
        return new CanonicalIdentityResolver(adminBff);
    }

    private static WebClientResponseException notFound() {
        return WebClientResponseException.create(404, "Not Found", HttpHeaders.EMPTY, new byte[0], null);
    }

    // ---------------------------- Matrix ----------------------------

    @Test
    void matrix_realJwt_noLocalpartClaim_resolvesOwnCasdoorAccount_notRawClaim() {
        HsTokenCustody custody = mock(HsTokenCustody.class);
        ServiceTokenBroker broker = mock(ServiceTokenBroker.class);
        AdminBffInternalClient adminBff = mock(AdminBffInternalClient.class);
        when(custody.cipherAvailable()).thenReturn(true);
        when(custody.loadAccessToken(anyString(), anyString())).thenReturn(Mono.empty());
        // The caller's OWN account, keyed casdoor:<email> (email wins the subject precedence).
        when(adminBff.getAccount("casdoor:alice@x.com")).thenReturn(Mono.just(
                new AdminBffInternalClient.AccountView("casdoor:alice@x.com", "casdoor", "alice@x.com",
                        true, List.of("user"), "aliceonhs")));
        when(broker.mintMatrix(anyString(), eq("aliceonhs")))
                .thenReturn(Mono.just(new MintedToken("native-tok", null, null, "aliceonhs")));

        MatrixProxyController controller = new MatrixProxyController(true, custody, broker,
                WebClient.builder().baseUrl("http://127.0.0.1:1").build(), resolver(adminBff));
        Jwt jwt = jwtWithClaims("casdoor-subject", java.util.Map.of("email", "alice@x.com"));

        // The downstream HTTP forward to the stub upstream inevitably errors (nothing is
        // listening) -- swallow it; only the mint resolution is under test here.
        controller.proxy(jwt, exchangeFor("/bff/user/matrix/_matrix/client/v3/sync"))
                .onErrorResume(e -> Mono.empty())
                .block(Duration.ofSeconds(10));

        verify(adminBff).getAccount("casdoor:alice@x.com");
        verify(broker).mintMatrix(anyString(), eq("aliceonhs"));
        // The OLD behaviour would have looked up google:<email> and/or minted the raw claim value.
        verify(adminBff, never()).getAccount("google:alice@x.com");
        verify(broker, never()).mintMatrix(anyString(), eq("alice@x.com"));
    }

    @Test
    void matrix_realJwt_noResolvableAccount_failsClosed_neverMints() {
        HsTokenCustody custody = mock(HsTokenCustody.class);
        ServiceTokenBroker broker = mock(ServiceTokenBroker.class);
        AdminBffInternalClient adminBff = mock(AdminBffInternalClient.class);
        when(custody.cipherAvailable()).thenReturn(true);
        when(custody.loadAccessToken(anyString(), anyString())).thenReturn(Mono.empty());
        // The caller's own casdoor: account does not exist (404) -- fail closed, NEVER a guess.
        when(adminBff.getAccount(anyString())).thenReturn(Mono.error(notFound()));

        MatrixProxyController controller = new MatrixProxyController(true, custody, broker,
                WebClient.builder().baseUrl("http://127.0.0.1:1").build(), resolver(adminBff));
        Jwt jwt = jwtWithClaims("casdoor-subject", java.util.Map.of("preferred_username", "mallory"));

        reactor.test.StepVerifier.create(
                        controller.proxy(jwt, exchangeFor("/bff/user/matrix/_matrix/client/v3/sync")))
                .expectErrorSatisfies(e -> assertThat(e).isInstanceOf(ResponseStatusException.class))
                .verify(Duration.ofSeconds(10));

        verify(broker, never()).mintMatrix(anyString(), anyString());
    }

    /**
     * THE TAKEOVER-REGRESSION TEST (Matrix). A real Casdoor JWT whose {@code preferred_username}
     * EQUALS an EXISTING {@code discord:} invite account's handle MUST resolve the caller's OWN
     * {@code casdoor:<handle>} account and mint under ITS localpart -- and must NEVER touch the
     * {@code discord:} victim account nor mint under the victim's localpart. Reverting the resolver
     * to the old raw {@code discord:} guess makes this test FAIL (it would call
     * {@code getAccount("discord:victim")} and mint {@code "victimlp"}).
     */
    @Test
    void matrix_realJwt_preferredUsernameCollidesWithVictimDiscordHandle_resolvesOwnCasdoorAccount_neverVictim() {
        HsTokenCustody custody = mock(HsTokenCustody.class);
        ServiceTokenBroker broker = mock(ServiceTokenBroker.class);
        AdminBffInternalClient adminBff = mock(AdminBffInternalClient.class);
        when(custody.cipherAvailable()).thenReturn(true);
        when(custody.loadAccessToken(anyString(), anyString())).thenReturn(Mono.empty());
        // The VICTIM: a discord invite account keyed on the SAME self-reported handle. Stubbed so
        // that IF the vulnerable guess ran, the mint would use the victim's localpart -- and the
        // assertions below would catch it.
        when(adminBff.getAccount("discord:victim")).thenReturn(Mono.just(
                new AdminBffInternalClient.AccountView("discord:victim", "discord", "victim",
                        true, List.of("user"), "victimlp")));
        // The CALLER's OWN account, in the caller's own casdoor namespace.
        when(adminBff.getAccount("casdoor:victim")).thenReturn(Mono.just(
                new AdminBffInternalClient.AccountView("casdoor:victim", "casdoor", "victim",
                        true, List.of("user"), "callerlp")));
        when(broker.mintMatrix(anyString(), eq("callerlp")))
                .thenReturn(Mono.just(new MintedToken("native-tok", null, null, "callerlp")));

        MatrixProxyController controller = new MatrixProxyController(true, custody, broker,
                WebClient.builder().baseUrl("http://127.0.0.1:1").build(), resolver(adminBff));
        Jwt jwt = jwtWithClaims("casdoor-uuid", java.util.Map.of("preferred_username", "victim"));

        controller.proxy(jwt, exchangeFor("/bff/user/matrix/_matrix/client/v3/sync"))
                .onErrorResume(e -> Mono.empty())
                .block(Duration.ofSeconds(10));

        verify(adminBff).getAccount("casdoor:victim");
        verify(broker).mintMatrix(anyString(), eq("callerlp"));
        // The takeover invariant: the victim's discord account is NEVER consulted, and the
        // victim's localpart is NEVER minted.
        verify(adminBff, never()).getAccount("discord:victim");
        verify(broker, never()).mintMatrix(anyString(), eq("victimlp"));
    }

    @Test
    void matrix_syntheticLocalpartClaim_usedDirectly_adminBffNeverCalled() {
        // The PRIMARY path is unaffected: when the localpart claim IS present (the native-login
        // synthetic Jwt), it is used as-is -- no admin-bff hop at all.
        HsTokenCustody custody = mock(HsTokenCustody.class);
        ServiceTokenBroker broker = mock(ServiceTokenBroker.class);
        AdminBffInternalClient adminBff = mock(AdminBffInternalClient.class);
        when(custody.cipherAvailable()).thenReturn(true);
        when(custody.loadAccessToken(anyString(), anyString())).thenReturn(Mono.empty());
        when(broker.mintMatrix(anyString(), eq("canonical-lp")))
                .thenReturn(Mono.just(new MintedToken("native-tok", null, null, "canonical-lp")));

        MatrixProxyController controller = new MatrixProxyController(true, custody, broker,
                WebClient.builder().baseUrl("http://127.0.0.1:1").build(), resolver(adminBff));
        Jwt jwt = jwtWithClaims("casdoor:uuid",
                java.util.Map.of("localpart", "canonical-lp", "preferred_username", "should-be-ignored"));

        controller.proxy(jwt, exchangeFor("/bff/user/matrix/_matrix/client/v3/sync"))
                .onErrorResume(e -> Mono.empty())
                .block(Duration.ofSeconds(10));

        verify(broker).mintMatrix(anyString(), eq("canonical-lp"));
        verify(adminBff, never()).getAccount(anyString());
    }

    // ---------------------------- Mastodon ----------------------------

    @Test
    void mastodon_realJwt_noLocalpartClaim_resolvesOwnCasdoorAccount_notRawClaim() {
        HsTokenCustody custody = mock(HsTokenCustody.class);
        ServiceTokenBroker broker = mock(ServiceTokenBroker.class);
        AdminBffInternalClient adminBff = mock(AdminBffInternalClient.class);
        when(custody.cipherAvailable()).thenReturn(true);
        when(custody.loadAccessToken(anyString(), anyString())).thenReturn(Mono.empty());
        when(adminBff.getAccount("casdoor:bobby")).thenReturn(Mono.just(
                new AdminBffInternalClient.AccountView("casdoor:bobby", "casdoor", "bobby",
                        true, List.of("user"), "bobonhs")));
        when(broker.mintMastodon(anyString(), eq("bobonhs")))
                .thenReturn(Mono.just(new MintedToken("native-tok", null, null, "bobonhs")));

        MastodonProxyController controller = new MastodonProxyController(true, custody, broker,
                WebClient.builder().baseUrl("http://127.0.0.1:1").build(), resolver(adminBff));
        Jwt jwt = jwtWithClaims("casdoor-subject", java.util.Map.of("preferred_username", "bobby"));

        controller.proxy(jwt, exchangeFor("/bff/user/mastodon/api/v1/timelines/home"))
                .onErrorResume(e -> Mono.empty())
                .block(Duration.ofSeconds(10));

        verify(adminBff).getAccount("casdoor:bobby");
        verify(broker).mintMastodon(anyString(), eq("bobonhs"));
        verify(adminBff, never()).getAccount("discord:bobby");
        verify(broker, never()).mintMastodon(anyString(), eq("bobby"));
    }

    @Test
    void mastodon_syntheticMastodonClaim_usedDirectly_adminBffNeverCalled() {
        // 291: the synthetic bff_ session Jwt carries the persisted mastodon_localpart claim --
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
                WebClient.builder().baseUrl("http://127.0.0.1:1").build(), resolver(adminBff));
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
        // (e.g. backfill-disambiguated) Mastodon value is "bob_disambig" -- the mint MUST use the
        // persisted value, or a backfilled colliding row would still be takeover-reachable.
        HsTokenCustody custody = mock(HsTokenCustody.class);
        ServiceTokenBroker broker = mock(ServiceTokenBroker.class);
        AdminBffInternalClient adminBff = mock(AdminBffInternalClient.class);
        when(custody.cipherAvailable()).thenReturn(true);
        when(custody.loadAccessToken(anyString(), anyString())).thenReturn(Mono.empty());
        when(adminBff.getAccount("casdoor:bobby")).thenReturn(Mono.just(
                new AdminBffInternalClient.AccountView("casdoor:bobby", "casdoor", "bobby",
                        true, List.of("user"), "bob.hs", "bob_disambig")));
        when(broker.mintMastodon(anyString(), eq("bob_disambig")))
                .thenReturn(Mono.just(new MintedToken("native-tok", null, null, "bob_disambig")));

        MastodonProxyController controller = new MastodonProxyController(true, custody, broker,
                WebClient.builder().baseUrl("http://127.0.0.1:1").build(), resolver(adminBff));
        Jwt jwt = jwtWithClaims("casdoor-subject", java.util.Map.of("preferred_username", "bobby"));

        controller.proxy(jwt, exchangeFor("/bff/user/mastodon/api/v1/timelines/home"))
                .onErrorResume(e -> Mono.empty())
                .block(Duration.ofSeconds(10));

        verify(broker).mintMastodon(anyString(), eq("bob_disambig"));
        verify(broker, never()).mintMastodon(anyString(), eq("bob_hs"));
    }

    @Test
    void mastodon_realJwt_onlySubClaim_resolvesOwnCasdoorAccountBySub_failsClosedOnMiss() {
        // No email / preferred_username -- only the sub claim. sub is the LAST subject-precedence
        // source (mirroring admin-bff's SUBJECT_CLAIMS), so the resolver looks up casdoor:<sub>.
        // Here it 404s -> fail closed, never mints.
        HsTokenCustody custody = mock(HsTokenCustody.class);
        ServiceTokenBroker broker = mock(ServiceTokenBroker.class);
        AdminBffInternalClient adminBff = mock(AdminBffInternalClient.class);
        when(custody.cipherAvailable()).thenReturn(true);
        when(custody.loadAccessToken(anyString(), anyString())).thenReturn(Mono.empty());
        when(adminBff.getAccount("casdoor:casdoor-subject")).thenReturn(Mono.error(notFound()));

        MastodonProxyController controller = new MastodonProxyController(true, custody, broker,
                WebClient.builder().baseUrl("http://127.0.0.1:1").build(), resolver(adminBff));
        Jwt jwt = jwtWithClaims("casdoor-subject", java.util.Map.of());

        reactor.test.StepVerifier.create(
                        controller.proxy(jwt, exchangeFor("/bff/user/mastodon/api/v1/timelines/home")))
                .expectErrorSatisfies(e -> assertThat(e).isInstanceOf(ResponseStatusException.class))
                .verify(Duration.ofSeconds(10));

        verify(adminBff).getAccount("casdoor:casdoor-subject");
        verify(broker, never()).mintMastodon(anyString(), anyString());
    }
}
