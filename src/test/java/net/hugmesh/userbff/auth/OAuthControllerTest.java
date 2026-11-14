package net.hugmesh.userbff.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.util.List;

import net.hugmesh.authcore.casdoor.BffCustodyCipher;
import net.hugmesh.userbff.profile.CasdoorUserClient;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.web.reactive.server.EntityExchangeResult;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Mono;

/**
 * {@link OAuthController} end to end against mocked Casdoor, admin-bff and provider calls
 * (hugmesh-generator#1107). What it pins: dark and per-domain refusal; the state cookie binds
 * the callback to the browser, the provider and the host; a linked account signs in through
 * the SAME completion as {@code /bff/login}; an unlinked one goes through the invite leg
 * (verified email, allowlist, account linked by the provider's id) and back to sign in;
 * every refusal creates nothing and lands on {@code /login?oauth=<reason>}.
 */
class OAuthControllerTest {

    static final String HOST = "mesh.example";
    static final String BASE = "https://" + HOST;

    CasdoorLoginClient casdoorLogin;
    OidcLoginCompletionService completion;
    AdminBffInternalClient adminBff;
    CasdoorUserClient casdoorUsers;
    OAuthIdentityClient identity;
    OAuthStateCodec codec;

    @BeforeEach
    void mocks() {
        casdoorLogin = mock(CasdoorLoginClient.class);
        completion = mock(OidcLoginCompletionService.class);
        adminBff = mock(AdminBffInternalClient.class);
        casdoorUsers = mock(CasdoorUserClient.class);
        identity = mock(OAuthIdentityClient.class);
        codec = new OAuthStateCodec(new BffCustodyCipher(OAuthPiecesTest.KEY), Clock.systemUTC());
    }

    WebTestClient client(boolean enabled, String domains) {
        OAuthController c = new OAuthController(OAuthPiecesTest.settings(enabled, domains), codec,
                identity, casdoorLogin, completion, adminBff, casdoorUsers, "app-user-bff",
                "https://hugmesh.net/login/callback", true);
        return WebTestClient.bindToController(c).configureClient().baseUrl(BASE).build();
    }

    WebTestClient live() {
        return client(true, HOST + "=password,google,discord");
    }

    /** /start, returning the sealed cookie and the provider redirect. */
    record Started(String cookie, URI location, String state) {}

    Started start(WebTestClient c, String provider) {
        EntityExchangeResult<byte[]> r = c.get().uri("/bff/oauth/" + provider + "/start")
                .exchange().expectStatus().isFound().expectBody().returnResult();
        URI loc = r.getResponseHeaders().getLocation();
        String setCookie = r.getResponseHeaders().getFirst("Set-Cookie");
        assertThat(setCookie).isNotNull().contains("HttpOnly", "Secure", "SameSite=Lax",
                "Path=/bff/oauth");
        String cookie = setCookie.substring(setCookie.indexOf('=') + 1, setCookie.indexOf(';'));
        String state = UriComponentsBuilder.fromUri(loc).build().getQueryParams().getFirst("state");
        return new Started(cookie, loc, state);
    }

    EntityExchangeResult<byte[]> callback(WebTestClient c, String provider, Started s, String code) {
        return c.get().uri("/bff/oauth/" + provider + "/callback?code=" + code + "&state=" + s.state())
                .cookie(OAuthStateCodec.COOKIE, s.cookie())
                .exchange().expectStatus().isFound().expectBody().returnResult();
    }

    static String location(EntityExchangeResult<byte[]> r) {
        return r.getResponseHeaders().getLocation().toString();
    }

    // ── dark and per domain ─────────────────────────────────────────────────────────────
    @Test
    void dark_offersNoProvider_andStartRefuses() {
        WebTestClient c = client(false, HOST + "=password,google");
        c.get().uri("/bff/oauth/providers").exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.providers.length()").isEqualTo(0);
        c.get().uri("/bff/oauth/google/start").exchange().expectStatus().isFound()
                .expectHeader().location("/login?oauth=unavailable");
    }

    @Test
    void providersFollowTheDomainList() {
        client(true, HOST + "=password,discord").get().uri("/bff/oauth/providers").exchange()
                .expectBody().jsonPath("$.providers[0]").isEqualTo("discord")
                .jsonPath("$.providers.length()").isEqualTo(1);
        client(true, HOST + "=password,discord").get().uri("/bff/oauth/google/start").exchange()
                .expectStatus().isFound().expectHeader().location("/login?oauth=unavailable");
        client(true, "other.example=google").get().uri("/bff/oauth/providers").exchange()
                .expectBody().jsonPath("$.providers.length()").isEqualTo(0);
    }

    @Test
    void start_redirectsToTheProviderWithItsCallbackOnThisHost() {
        Started s = start(live(), "google");
        assertThat(s.location().toString()).startsWith(OAuthProvider.GOOGLE.authorizeUrl() + "?");
        var q = UriComponentsBuilder.fromUri(s.location()).build().getQueryParams();
        assertThat(q.getFirst("client_id")).isEqualTo("g-id");
        assertThat(q.getFirst("redirect_uri"))
                .isEqualTo("https://mesh.example/bff/oauth/google/callback");
        assertThat(s.location().toString()).doesNotContain("g-secret");
        assertThat(s.state()).startsWith("app-user-bff-org-");
    }

    // ── the binding ─────────────────────────────────────────────────────────────────────
    @Test
    void callback_withoutTheCookie_orAnotherState_orAnotherProvider_isRefused() {
        WebTestClient c = live();
        Started s = start(c, "google");
        c.get().uri("/bff/oauth/google/callback?code=x&state=" + s.state()).exchange()
                .expectStatus().isFound().expectHeader().location("/login?oauth=expired");
        c.get().uri("/bff/oauth/google/callback?code=x&state=app-user-bff-org-forged")
                .cookie(OAuthStateCodec.COOKIE, s.cookie()).exchange()
                .expectStatus().isFound().expectHeader().location("/login?oauth=expired");
        c.get().uri("/bff/oauth/discord/callback?code=x&state=" + s.state())
                .cookie(OAuthStateCodec.COOKIE, s.cookie()).exchange()
                .expectStatus().isFound().expectHeader().location("/login?oauth=expired");
        WebTestClient otherHost = WebTestClient.bindToController(new OAuthController(
                        OAuthPiecesTest.settings(true, "example=google"), codec, identity, casdoorLogin,
                        completion, adminBff, casdoorUsers, "app-user-bff", "https://x/cb", true))
                .configureClient().baseUrl("https://shop.example").build();
        otherHost.get().uri("/bff/oauth/google/callback?code=x&state=" + s.state())
                .cookie(OAuthStateCodec.COOKIE, s.cookie()).exchange()
                .expectStatus().isFound().expectHeader().location("/login?oauth=expired");
        verifyNoInteractions(casdoorLogin, identity, adminBff, casdoorUsers);
    }

    @Test
    void theProvidersOwnRefusalIsDenied() {
        WebTestClient c = live();
        Started s = start(c, "discord");
        c.get().uri("/bff/oauth/discord/callback?error=access_denied&state=" + s.state())
                .cookie(OAuthStateCodec.COOKIE, s.cookie()).exchange()
                .expectStatus().isFound().expectHeader().location("/login?oauth=denied");
        verifyNoInteractions(casdoorLogin);
    }

    // ── sign-in ─────────────────────────────────────────────────────────────────────────
    @Test
    void aLinkedAccountSignsInThroughTheSameCompletion() {
        WebTestClient c = live();
        Started s = start(c, "google");
        when(casdoorLogin.loginWithProvider(eq("google"), eq("pcode"), eq(s.state()), anyString(),
                eq("https://hugmesh.net/login/callback"),
                eq("https://mesh.example/bff/oauth/google/callback")))
                .thenReturn(Mono.just(CasdoorLoginClient.CasdoorLoginResult.code("casdoor-code")));
        when(completion.complete(eq("casdoor-code"), anyString(),
                eq("https://hugmesh.net/login/callback"), any()))
                .thenReturn(Mono.just(new OidcLoginCompletionService.Completed(true, "active")));
        EntityExchangeResult<byte[]> r = callback(c, "google", s, "pcode");
        assertThat(location(r)).isEqualTo("/");
        assertThat(r.getResponseHeaders().get("Set-Cookie"))
                .anyMatch(h -> h.startsWith(OAuthStateCodec.COOKIE + "=;") && h.contains("Max-Age=0"));
        verifyNoInteractions(identity, adminBff, casdoorUsers);
    }

    @Test
    void mfaSendsThePersonToThePasswordForm() {
        WebTestClient c = live();
        Started s = start(c, "google");
        when(casdoorLogin.loginWithProvider(anyString(), anyString(), anyString(), anyString(),
                anyString(), anyString()))
                .thenReturn(Mono.just(CasdoorLoginClient.CasdoorLoginResult.mfaRequired(List.of("totp"))));
        assertThat(location(callback(c, "google", s, "pcode"))).isEqualTo("/login?oauth=mfa");
        verify(completion, never()).complete(anyString(), anyString(), anyString(), any());
    }

    @Test
    void anyOtherCasdoorErrorIsAFailure() {
        WebTestClient c = live();
        Started s = start(c, "google");
        when(casdoorLogin.loginWithProvider(anyString(), anyString(), anyString(), anyString(),
                anyString(), anyString()))
                .thenReturn(Mono.just(CasdoorLoginClient.CasdoorLoginResult.error("Invalid token")));
        assertThat(location(callback(c, "google", s, "pcode"))).isEqualTo("/login?oauth=failed");
        when(casdoorLogin.loginWithProvider(anyString(), anyString(), anyString(), anyString(),
                anyString(), anyString())).thenReturn(Mono.error(new RuntimeException("down")));
        Started s2 = start(c, "google");
        assertThat(location(callback(c, "google", s2, "pcode"))).isEqualTo("/login?oauth=failed");
    }

    // ── the invite leg ──────────────────────────────────────────────────────────────────
    static final String UNKNOWN = "The account for provider: Google and username: a (A) does not "
            + "exist and is not allowed to sign up as new account, please contact your IT support";

    /** An unlinked person: Casdoor refuses, and the callback sends them back for SIGNUP. */
    Started unlinked(WebTestClient c, String provider) {
        Started s = start(c, provider);
        when(casdoorLogin.loginWithProvider(anyString(), anyString(), anyString(), anyString(),
                anyString(), anyString()))
                .thenReturn(Mono.just(CasdoorLoginClient.CasdoorLoginResult.error(UNKNOWN)));
        EntityExchangeResult<byte[]> r = callback(c, provider, s, "first");
        URI loc = r.getResponseHeaders().getLocation();
        assertThat(loc.toString()).startsWith(OAuthProvider.byId(provider).get().authorizeUrl());
        String setCookie = r.getResponseHeaders().getFirst("Set-Cookie");
        String cookie = setCookie.substring(setCookie.indexOf('=') + 1, setCookie.indexOf(';'));
        assertThat(codec.open(cookie).get().phase()).isEqualTo(OAuthStateCodec.Phase.SIGNUP);
        return new Started(cookie, loc,
                UriComponentsBuilder.fromUri(loc).build().getQueryParams().getFirst("state"));
    }

    @Test
    void anInvitedGooglePersonGetsALinkedAccountThenSignsIn() {
        WebTestClient c = live();
        Started up = unlinked(c, "google");
        when(identity.identify(eq(OAuthProvider.GOOGLE), any(), eq("second"),
                eq("https://mesh.example/bff/oauth/google/callback")))
                .thenReturn(Mono.just(new OAuthIdentityClient.Identity("sub-1", "alice.w@example.org", "")));
        when(adminBff.allowlistCheck("google", "alice.w@example.org")).thenReturn(Mono.just(true));
        when(casdoorUsers.addLinkedUser("alice_w", "", "alice.w@example.org", "google", "sub-1"))
                .thenReturn(Mono.empty());
        EntityExchangeResult<byte[]> r = callback(c, "google", up, "second");
        assertThat(location(r)).startsWith(OAuthProvider.GOOGLE.authorizeUrl());
        String setCookie = r.getResponseHeaders().getFirst("Set-Cookie");
        String cookie = setCookie.substring(setCookie.indexOf('=') + 1, setCookie.indexOf(';'));
        assertThat(codec.open(cookie).get().phase()).isEqualTo(OAuthStateCodec.Phase.SIGNIN);
        verify(casdoorUsers).addLinkedUser("alice_w", "", "alice.w@example.org", "google", "sub-1");
    }

    @Test
    void anInvitedDiscordPersonIsCheckedByUsernameAndLinkedById() {
        WebTestClient c = live();
        Started up = unlinked(c, "discord");
        when(identity.identify(eq(OAuthProvider.DISCORD), any(), eq("second"), anyString()))
                .thenReturn(Mono.just(new OAuthIdentityClient.Identity("777", "", "bob.two")));
        when(adminBff.allowlistCheck("discord", "bob.two")).thenReturn(Mono.just(true));
        when(casdoorUsers.addLinkedUser(anyString(), anyString(), anyString(), anyString(), anyString()))
                .thenReturn(Mono.empty());
        callback(c, "discord", up, "second");
        verify(casdoorUsers).addLinkedUser("bob_two", "bob.two", "", "discord", "777");
    }

    @Test
    void notInvited_createsNothing() {
        WebTestClient c = live();
        Started up = unlinked(c, "google");
        when(identity.identify(any(), any(), anyString(), anyString()))
                .thenReturn(Mono.just(new OAuthIdentityClient.Identity("sub-1", "eve@example.org", "")));
        when(adminBff.allowlistCheck("google", "eve@example.org")).thenReturn(Mono.just(false));
        assertThat(location(callback(c, "google", up, "second"))).isEqualTo("/login?oauth=not_invited");
        verifyNoInteractions(casdoorUsers);
    }

    @Test
    void anUnverifiedGoogleEmailIsNeverAnInvite() {
        WebTestClient c = live();
        Started up = unlinked(c, "google");
        when(identity.identify(any(), any(), anyString(), anyString()))
                .thenReturn(Mono.just(new OAuthIdentityClient.Identity("sub-1", "", "")));
        assertThat(location(callback(c, "google", up, "second"))).isEqualTo("/login?oauth=unverified");
        verifyNoInteractions(adminBff, casdoorUsers);
    }

    @Test
    void aTakenName_isSaidSo() {
        WebTestClient c = live();
        Started up = unlinked(c, "discord");
        when(identity.identify(any(), any(), anyString(), anyString()))
                .thenReturn(Mono.just(new OAuthIdentityClient.Identity("777", "", "bob")));
        when(adminBff.allowlistCheck("discord", "bob")).thenReturn(Mono.just(true));
        when(casdoorUsers.addLinkedUser(anyString(), anyString(), anyString(), anyString(), anyString()))
                .thenReturn(Mono.error(new RuntimeException(
                        "identity provider refused add-user: The user: hugmesh/bob already exists")));
        assertThat(location(callback(c, "discord", up, "second"))).isEqualTo("/login?oauth=taken");
    }

    @Test
    void aReservedOrEmptyNameIsNeverCreated() {
        assertThat(OAuthController.usernameFor(OAuthProvider.DISCORD,
                new OAuthIdentityClient.Identity("1", "", "admin"))).isEmpty();
        assertThat(OAuthController.usernameFor(OAuthProvider.GOOGLE,
                new OAuthIdentityClient.Identity("1", "--@x.org", ""))).isEmpty();
        assertThat(OAuthController.usernameFor(OAuthProvider.GOOGLE,
                new OAuthIdentityClient.Identity("1", "Ann.Lee+x@x.org", ""))).isEqualTo("ann_lee_x");
    }

    @Test
    void aSecondCallbackWithTheSameCookieIsRefused_theCookieIsSpent() {
        WebTestClient c = live();
        Started s = start(c, "google");
        when(casdoorLogin.loginWithProvider(anyString(), anyString(), anyString(), anyString(),
                anyString(), anyString()))
                .thenReturn(Mono.just(CasdoorLoginClient.CasdoorLoginResult.error("Invalid token")));
        EntityExchangeResult<byte[]> r = callback(c, "google", s, "pcode");
        assertThat(r.getResponseHeaders().getFirst("Set-Cookie")).contains("Max-Age=0");
        assertThat(Duration.ofMinutes(10)).isEqualTo(OAuthPiecesTest.settings(true, "").stateTtl());
    }
}
