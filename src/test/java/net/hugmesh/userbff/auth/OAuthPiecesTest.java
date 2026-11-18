package net.hugmesh.userbff.auth;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

import net.hugmesh.authcore.casdoor.BffCustodyCipher;
import net.hugmesh.userbff.profile.CasdoorUserClient;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.mock.http.client.reactive.MockClientHttpRequest;
import reactor.core.publisher.Mono;

/**
 * The parts of the Google/Discord sign-in (hugmesh-generator#1107) below the controller:
 * the settings (dark by default, per-domain, fail closed), the sealed state cookie, the
 * provider identity parse (verified emails only), and the two Casdoor calls.
 */
class OAuthPiecesTest {

    static final String KEY = "0123456789abcdef0123456789abcdef";

    static OAuthSettings settings(boolean enabled, String domains) {
        Map<OAuthProvider, OAuthSettings.Client> c = new EnumMap<>(OAuthProvider.class);
        c.put(OAuthProvider.GOOGLE, new OAuthSettings.Client("g-id", "g-secret"));
        c.put(OAuthProvider.DISCORD, new OAuthSettings.Client("d-id", "d-secret"));
        return new OAuthSettings(enabled, Duration.ofMinutes(10), c, domains);
    }

    // ── settings ────────────────────────────────────────────────────────────────────
    @Test
    void dark_offersNothing() {
        assertThat(settings(false, "mesh.example=password,google").providersFor("mesh.example"))
                .isEmpty();
    }

    @Test
    void perDomain_longestMatchWins_andAnUnlistedHostGetsNothing() {
        OAuthSettings s = settings(true,
                "mesh.example=password,google ; shop.mesh.example=password,discord;bad;=x;");
        assertThat(s.providersFor("mesh.example")).containsExactly(OAuthProvider.GOOGLE);
        assertThat(s.providersFor("login.mesh.example")).containsExactly(OAuthProvider.GOOGLE);
        assertThat(s.providersFor("shop.mesh.example")).containsExactly(OAuthProvider.DISCORD);
        assertThat(s.providersFor("x.shop.mesh.example")).containsExactly(OAuthProvider.DISCORD);
        assertThat(s.providersFor("evilmesh.example")).isEmpty();
        assertThat(s.providersFor("other.example")).isEmpty();
        assertThat(s.providersFor("")).isEmpty();
    }

    @Test
    void anUnconfiguredClientIsNeverOffered() {
        Map<OAuthProvider, OAuthSettings.Client> c = new EnumMap<>(OAuthProvider.class);
        c.put(OAuthProvider.GOOGLE, new OAuthSettings.Client("g-id", ""));
        OAuthSettings s = new OAuthSettings(true, null, c, "mesh.example=google,discord");
        assertThat(s.providersFor("mesh.example")).isEmpty();
        assertThat(s.client(OAuthProvider.GOOGLE)).isEmpty();
        assertThat(new OAuthSettings.Client("id", "s3cret").toString()).doesNotContain("s3cret");
    }

    // ── the sealed state ────────────────────────────────────────────────────────────
    private static OAuthStateCodec codec(Instant now) {
        return new OAuthStateCodec(new BffCustodyCipher(KEY), Clock.fixed(now, ZoneOffset.UTC));
    }

    @Test
    void state_roundTrips_andSatisfiesCasdoorsPrefixCheck() {
        Instant now = Instant.parse("2026-11-13T12:00:00Z");
        OAuthStateCodec c = codec(now);
        OAuthStateCodec.State s = c.issue(OAuthProvider.GOOGLE, OAuthStateCodec.Phase.SIGNUP,
                "app-user-bff", "mesh.example", Duration.ofMinutes(10));
        assertThat(s.state().split("-org-")[0]).isEqualTo("app-user-bff");
        String sealed = c.seal(s);
        assertThat(sealed).doesNotContain("+", "/", "=", "mesh.example");
        assertThat(c.open(sealed)).contains(s);
    }

    @Test
    void state_expired_tampered_foreignOrCustodyBlob_doesNotOpen() {
        Instant now = Instant.parse("2026-11-13T12:00:00Z");
        OAuthStateCodec c = codec(now);
        OAuthStateCodec.State s = c.issue(OAuthProvider.DISCORD, OAuthStateCodec.Phase.SIGNIN,
                "app-user-bff", "mesh.example", Duration.ofMinutes(10));
        String sealed = c.seal(s);
        assertThat(codec(now.plusSeconds(601)).open(sealed)).isEmpty();
        // flip a character in the MIDDLE (the last one can carry only padding bits, so
        // changing it need not change the decoded bytes)
        int mid = sealed.length() / 2;
        char ch = sealed.charAt(mid);
        assertThat(c.open(sealed.substring(0, mid) + (ch == 'A' ? 'B' : 'A')
                + sealed.substring(mid + 1))).isEmpty();
        OAuthStateCodec other = new OAuthStateCodec(
                new BffCustodyCipher("ffffffffffffffffffffffffffffffff"), Clock.fixed(now, ZoneOffset.UTC));
        assertThat(other.open(sealed)).isEmpty();
        // a custody blob (an encrypted access token) is not a state cookie
        String custody = new BffCustodyCipher(KEY).encrypt("eyJ.access.token")
                .replace('+', '-').replace('/', '_').replace("=", "");
        assertThat(c.open(custody)).isEmpty();
        assertThat(c.open(null)).isEmpty();
        assertThat(new OAuthStateCodec(new BffCustodyCipher(""), Clock.systemUTC()).available())
                .isFalse();
    }

    // ── the provider identity ───────────────────────────────────────────────────────
    @Test
    void identity_keepsOnlyVerifiedEmails() {
        assertThat(OAuthIdentityClient.parse(OAuthProvider.GOOGLE,
                Map.of("sub", "123", "email", "Alice@Example.org", "email_verified", true)))
                .isEqualTo(new OAuthIdentityClient.Identity("123", "alice@example.org", ""));
        assertThat(OAuthIdentityClient.parse(OAuthProvider.GOOGLE,
                Map.of("sub", "123", "email", "alice@example.org", "email_verified", false)).email())
                .isEmpty();
        assertThat(OAuthIdentityClient.parse(OAuthProvider.DISCORD,
                Map.of("id", "9", "username", "Bob_2", "email", "b@x.org", "verified", "true")))
                .isEqualTo(new OAuthIdentityClient.Identity("9", "b@x.org", "bob_2"));
        assertThat(OAuthIdentityClient.parse(OAuthProvider.DISCORD,
                Map.of("id", "9", "username", "bob", "email", "b@x.org")).email()).isEmpty();
    }

    @Test
    void identity_exchangesAtTheProvidersOwnEndpoints() {
        List<ClientRequest> seen = new ArrayList<>();
        ExchangeFunction fn = req -> {
            seen.add(req);
            String body = req.url().toString().equals(OAuthProvider.GOOGLE.tokenUrl())
                    ? "{\"access_token\":\"at-1\"}"
                    : "{\"sub\":\"123\",\"email\":\"a@b.org\",\"email_verified\":true}";
            return Mono.just(ClientResponse.create(HttpStatus.OK)
                    .header("Content-Type", MediaType.APPLICATION_JSON_VALUE).body(body).build());
        };
        OAuthIdentityClient.Identity who = new OAuthIdentityClient(
                WebClient.builder().exchangeFunction(fn).build())
                .identify(OAuthProvider.GOOGLE, new OAuthSettings.Client("g-id", "g-secret"),
                        "code-1", "https://mesh.example/bff/oauth/google/callback")
                .block();
        assertThat(who).isEqualTo(new OAuthIdentityClient.Identity("123", "a@b.org", ""));
        assertThat(seen).hasSize(2);
        assertThat(seen.get(0).url().toString()).isEqualTo(OAuthProvider.GOOGLE.tokenUrl());
        String form = body(seen.get(0));
        assertThat(form).contains("code=code-1", "client_secret=g-secret",
                "redirect_uri=https%3A%2F%2Fmesh.example%2Fbff%2Foauth%2Fgoogle%2Fcallback");
        assertThat(seen.get(1).url().toString()).isEqualTo(OAuthProvider.GOOGLE.userinfoUrl());
        assertThat(seen.get(1).headers().getFirst("Authorization")).isEqualTo("Bearer at-1");
    }

    // ── the two Casdoor calls ───────────────────────────────────────────────────────
    @Test
    void casdoorProviderLogin_postsTheProviderCodeWithBothRedirects() {
        List<ClientRequest> seen = new ArrayList<>();
        ExchangeFunction fn = req -> {
            seen.add(req);
            return Mono.just(ClientResponse.create(HttpStatus.OK)
                    .header("Content-Type", MediaType.APPLICATION_JSON_VALUE)
                    .body("{\"status\":\"ok\",\"data\":\"casdoor-code\"}").build());
        };
        CasdoorLoginClient client = new CasdoorLoginClient(
                WebClient.builder().baseUrl("http://casdoor:8000").exchangeFunction(fn).build(),
                "/api/login", "app-user-bff", "app-user-bff", "hugmesh", "openid profile email");
        CasdoorLoginClient.CasdoorLoginResult r = client.loginWithProvider("google", "pcode",
                "app-user-bff-org-xyz", "chal", "https://hugmesh.net/login/callback",
                "https://mesh.example/bff/oauth/google/callback").block();
        assertThat(r.kind()).isEqualTo(CasdoorLoginClient.CasdoorLoginResult.Kind.CODE);
        String url = seen.get(0).url().toString();
        assertThat(url).contains("redirectUri=https://hugmesh.net/login/callback",
                "code_challenge=chal", "state=app-user-bff-org-xyz");
        String json = body(seen.get(0));
        assertThat(json).contains("\"provider\":\"google\"", "\"code\":\"pcode\"",
                "\"method\":\"signin\"", "\"type\":\"code\"",
                "\"redirectUri\":\"https://mesh.example/bff/oauth/google/callback\"");
        assertThat(json).doesNotContain("password");
    }

    @Test
    void unknownAccountIsCasdoorsSignUpDisabledRefusalOnly() {
        assertThat(CasdoorLoginClient.isUnknownAccount("The account for provider: Google and "
                + "username: a (A) does not exist and is not allowed to sign up as new account, "
                + "please contact your IT support")).isTrue();
        assertThat(CasdoorLoginClient.isUnknownAccount("Invalid token")).isFalse();
        assertThat(CasdoorLoginClient.isUnknownAccount(null)).isFalse();
    }

    @Test
    void addLinkedUser_writesTheProviderIdIntoItsLinkField_andFailsClosedWhenDark() {
        List<ClientRequest> seen = new ArrayList<>();
        ExchangeFunction fn = req -> {
            seen.add(req);
            return Mono.just(ClientResponse.create(HttpStatus.OK)
                    .header("Content-Type", MediaType.APPLICATION_JSON_VALUE)
                    .body("{\"status\":\"ok\"}").build());
        };
        new CasdoorUserClient(WebClient.builder().baseUrl("http://casdoor:8000")
                .exchangeFunction(fn).build(), "hugmesh")
                .addLinkedUser("bob_2", "bob_2", "", "discord", "9").block();
        assertThat(seen.get(0).url().getPath()).isEqualTo("/api/add-user");
        String json = body(seen.get(0));
        assertThat(json).contains("\"owner\":\"hugmesh\"", "\"name\":\"bob_2\"",
                "\"discord\":\"9\"", "\"type\":\"normal-user\"");
        assertThat(json).doesNotContain("\"email\"");
        org.assertj.core.api.Assertions.assertThatThrownBy(() ->
                new CasdoorUserClient(null, "hugmesh")
                        .addLinkedUser("bob_2", "", "", "discord", "9").block())
                .hasMessageContaining("disabled");
    }

    @Test
    void addLinkedUser_surfacesCasdoorsRefusal() {
        ExchangeFunction fn = req -> Mono.just(ClientResponse.create(HttpStatus.OK)
                .header("Content-Type", MediaType.APPLICATION_JSON_VALUE)
                .body("{\"status\":\"error\",\"msg\":\"The user: hugmesh/bob already exists\"}")
                .build());
        org.assertj.core.api.Assertions.assertThatThrownBy(() ->
                new CasdoorUserClient(WebClient.builder().exchangeFunction(fn).build(), "hugmesh")
                        .addLinkedUser("bob", "", "", "discord", "9").block())
                .hasMessageContaining("exist");
    }

    /** The serialized body of a captured request. */
    static String body(ClientRequest req) {
        MockClientHttpRequest out = new MockClientHttpRequest(req.method(), req.url());
        req.body().insert(out, new org.springframework.web.reactive.function.BodyInserter.Context() {
            @Override
            public java.util.List<org.springframework.http.codec.HttpMessageWriter<?>> messageWriters() {
                return org.springframework.http.codec.ClientCodecConfigurer.create().getWriters();
            }

            @Override
            public java.util.Optional<org.springframework.http.server.reactive.ServerHttpRequest> serverRequest() {
                return java.util.Optional.empty();
            }

            @Override
            public java.util.Map<String, Object> hints() {
                return java.util.Map.of();
            }
        }).block();
        return out.getBodyAsString().block();
    }

    @SuppressWarnings("unused")
    private static String utf8(DataBuffer b) {
        return b.toString(StandardCharsets.UTF_8);
    }
}
