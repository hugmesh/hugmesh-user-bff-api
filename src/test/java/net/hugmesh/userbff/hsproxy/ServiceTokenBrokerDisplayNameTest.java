package net.hugmesh.userbff.hsproxy;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.mock.http.client.reactive.MockClientHttpRequest;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import org.springframework.web.reactive.function.client.ExchangeStrategies;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.net.URI;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;
import java.util.function.Supplier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * The post-mint homeserver display-name reconcile.
 *
 * <p>The defect: a Casdoor account without an email is persisted with localpart = the Casdoor
 * UUID, and neither homeserver registration call carried a name, so Matrix showed
 * {@code c18f905c-62a1-4c20-a7c5-c707fb6eae85 💕} (tuwunel's default) and Mastodon/Akkoma an
 * empty display_name (the truncated-UUID @handle) wherever the person's username belonged.
 * These drive the real broker through a stub homeserver that records every request, and pin:
 * the name is written on the register AND the login/recover legs; only over a DEFAULT name;
 * never when the name is unknown; and a failing profile call never fails the mint.
 */
class ServiceTokenBrokerDisplayNameTest {

    private static final String UUID = "c18f905c-62a1-4c20-a7c5-c707fb6eae85";
    private static final String MXID = "@" + UUID + ":hugmesh.local";
    /** The literal wire path: {@code @} and {@code :} percent-encoded, as Matrix clients send. */
    private static final String PROFILE_PATH =
            "/_matrix/client/v3/profile/%40" + UUID + "%3Ahugmesh.local/displayname";
    private static final String MASTODON_LP = "c18f905c_62a1_4c20_a7c5_c707fb";

    /** One recorded request: method, RAW path, body. */
    record Seen(String method, String rawPath, String body) {}

    /** Routes by {@code METHOD rawPath}; each route's responses are consumed IN ORDER (last
     *  repeats). Responses are built fresh per request (a ClientResponse body is single-use). */
    static final class Homeserver implements ExchangeFunction {
        final Map<String, List<Supplier<ClientResponse>>> routes = new HashMap<>();
        final Map<String, AtomicInteger> hits = new HashMap<>();
        final List<Seen> seen = new ArrayList<>();

        Homeserver on(String method, String rawPath, HttpStatus status, String body) {
            routes.computeIfAbsent(method + " " + rawPath, k -> new ArrayList<>())
                    .add(() -> ClientResponse.create(status)
                            .header("Content-Type", MediaType.APPLICATION_JSON_VALUE)
                            .body(body).build());
            return this;
        }

        @Override
        public Mono<ClientResponse> exchange(ClientRequest request) {
            String key = request.method().name() + " " + request.url().getRawPath();
            MockClientHttpRequest sink = new MockClientHttpRequest(HttpMethod.POST, URI.create("http://hs.test"));
            return request.writeTo(sink, ExchangeStrategies.withDefaults())
                    .then(Mono.defer(sink::getBodyAsString))
                    .defaultIfEmpty("")
                    .map(body -> {
                        seen.add(new Seen(request.method().name(), request.url().getRawPath(), body));
                        List<Supplier<ClientResponse>> rs = routes.get(key);
                        if (rs == null) {
                            return ClientResponse.create(HttpStatus.NOT_FOUND)
                                    .header("Content-Type", MediaType.APPLICATION_JSON_VALUE)
                                    .body("{\"errcode\":\"M_UNRECOGNIZED\",\"error\":\"unrouted " + key + "\"}")
                                    .build();
                        }
                        int n = hits.computeIfAbsent(key, k -> new AtomicInteger()).getAndIncrement();
                        return rs.get(Math.min(n, rs.size() - 1)).get();
                    });
        }

        List<Seen> writes() {
            return seen.stream().filter(s -> s.method().equals("PUT") || s.method().equals("PATCH")).toList();
        }
    }

    private final HsTokenCustody custody = mock(HsTokenCustody.class);

    private ServiceTokenBroker broker(Homeserver hs, Function<String, Mono<String>> names) {
        when(custody.upsert(any(), any(), any(), any(), any(), any())).thenReturn(Mono.empty());
        HsTokenRevocationHashWriter hashWriter = mock(HsTokenRevocationHashWriter.class);
        when(hashWriter.recordBrokered(any(), any(), any())).thenReturn(Mono.empty());
        WebClient client = WebClient.builder().exchangeFunction(hs).build();
        return new ServiceTokenBroker(client, client, "svc-pw", "e2e.local", custody, hashWriter, names);
    }

    private static Function<String, Mono<String>> name(String n) {
        return owner -> Mono.just(n);
    }

    // ── Matrix ─────────────────────────────────────────────────────────────────

    @Test
    void matrix_registerLeg_replacesTuwunelDefaultWithTheUsername() {
        Homeserver hs = new Homeserver()
                .on("POST", "/_matrix/client/v3/register", HttpStatus.OK,
                        "{\"access_token\":\"syt_new\",\"user_id\":\"" + MXID + "\"}")
                .on("GET", PROFILE_PATH, HttpStatus.OK, "{\"displayname\":\"" + UUID + " 💕\"}")
                .on("PUT", PROFILE_PATH, HttpStatus.OK, "{}");

        StepVerifier.create(broker(hs, name("e2e-matrix")).mintMatrix("casdoor:" + UUID, UUID))
                .assertNext(t -> assertThat(t.accessToken()).isEqualTo("syt_new"))
                .verifyComplete();

        assertThat(hs.writes()).hasSize(1);
        assertThat(hs.writes().get(0).rawPath()).isEqualTo(PROFILE_PATH);
        assertThat(hs.writes().get(0).body()).isEqualTo("{\"displayname\":\"e2e-matrix\"}");
    }

    @Test
    void matrix_loginLeg_existingAccountWithNoDisplayname_getsTheUsername() {
        // Already registered (M_USER_IN_USE) -> password login; the profile has NO displayname (404).
        Homeserver hs = new Homeserver()
                .on("POST", "/_matrix/client/v3/register", HttpStatus.BAD_REQUEST,
                        "{\"errcode\":\"M_USER_IN_USE\"}")
                .on("POST", "/_matrix/client/v3/login", HttpStatus.OK,
                        "{\"access_token\":\"syt_login\",\"user_id\":\"" + MXID + "\"}")
                .on("GET", PROFILE_PATH, HttpStatus.NOT_FOUND, "{\"errcode\":\"M_NOT_FOUND\"}")
                .on("PUT", PROFILE_PATH, HttpStatus.OK, "{}");

        StepVerifier.create(broker(hs, name("e2e-matrix")).mintMatrix("casdoor:" + UUID, UUID))
                .assertNext(t -> assertThat(t.accessToken()).isEqualTo("syt_login"))
                .verifyComplete();

        assertThat(hs.writes()).extracting(Seen::body).containsExactly("{\"displayname\":\"e2e-matrix\"}");
    }

    @Test
    void matrix_aNameThePersonChose_isNeverOverwritten() {
        Homeserver hs = new Homeserver()
                .on("POST", "/_matrix/client/v3/register", HttpStatus.OK,
                        "{\"access_token\":\"syt_new\",\"user_id\":\"" + MXID + "\"}")
                .on("GET", PROFILE_PATH, HttpStatus.OK, "{\"displayname\":\"Matrix Fan 💕\"}")
                .on("PUT", PROFILE_PATH, HttpStatus.OK, "{}");

        StepVerifier.create(broker(hs, name("e2e-matrix")).mintMatrix("casdoor:" + UUID, UUID))
                .expectNextCount(1).verifyComplete();

        assertThat(hs.writes()).isEmpty();
    }

    @Test
    void matrix_unknownName_makesNoProfileCallAtAll() {
        Homeserver hs = new Homeserver()
                .on("POST", "/_matrix/client/v3/register", HttpStatus.OK,
                        "{\"access_token\":\"syt_new\",\"user_id\":\"" + MXID + "\"}");

        StepVerifier.create(broker(hs, name("")).mintMatrix("casdoor:" + UUID, UUID))
                .expectNextCount(1).verifyComplete();

        assertThat(hs.seen).extracting(Seen::rawPath).containsExactly("/_matrix/client/v3/register");
    }

    @Test
    void matrix_profileFailures_neverFailTheMint_andCustodyIsStillWritten() {
        Homeserver hs = new Homeserver()
                .on("POST", "/_matrix/client/v3/register", HttpStatus.OK,
                        "{\"access_token\":\"syt_new\",\"user_id\":\"" + MXID + "\"}")
                .on("GET", PROFILE_PATH, HttpStatus.OK, "{}")
                .on("PUT", PROFILE_PATH, HttpStatus.INTERNAL_SERVER_ERROR, "{\"errcode\":\"M_UNKNOWN\"}");

        StepVerifier.create(broker(hs, name("e2e-matrix")).mintMatrix("casdoor:" + UUID, UUID))
                .assertNext(t -> assertThat(t.accessToken()).isEqualTo("syt_new"))
                .verifyComplete();
        verify(custody).upsert(any(), any(), any(), any(), any(), any());

        // A lookup that ERRORS (admin-bff down) is equally harmless.
        Homeserver hs2 = new Homeserver()
                .on("POST", "/_matrix/client/v3/register", HttpStatus.OK,
                        "{\"access_token\":\"syt_2\",\"user_id\":\"" + MXID + "\"}");
        StepVerifier.create(broker(hs2, owner -> Mono.error(new IllegalStateException("admin-bff down")))
                        .mintMatrix("casdoor:" + UUID, UUID))
                .assertNext(t -> assertThat(t.accessToken()).isEqualTo("syt_2"))
                .verifyComplete();
    }

    @Test
    void matrixDefaultDetection() {
        assertThat(ServiceTokenBroker.isDefaultMatrixDisplayName(null, "bob")).isTrue();
        assertThat(ServiceTokenBroker.isDefaultMatrixDisplayName("", "bob")).isTrue();
        assertThat(ServiceTokenBroker.isDefaultMatrixDisplayName("bob", "bob")).isTrue();
        assertThat(ServiceTokenBroker.isDefaultMatrixDisplayName("bob 💕", "bob")).isTrue();
        assertThat(ServiceTokenBroker.isDefaultMatrixDisplayName("bob ⚡️", "bob")).isTrue();
        assertThat(ServiceTokenBroker.isDefaultMatrixDisplayName("bob the builder", "bob")).isFalse();
        assertThat(ServiceTokenBroker.isDefaultMatrixDisplayName("Bob", "bob")).isFalse();
    }

    // ── Mastodon / Akkoma ───────────────────────────────────────────────────────

    private static Homeserver mastodonRecover(String displayName) {
        return new Homeserver()
                .on("POST", "/api/v1/apps", HttpStatus.OK, "{\"client_id\":\"cid\",\"client_secret\":\"cs\"}")
                .on("POST", "/oauth/token", HttpStatus.OK, "{\"access_token\":\"mst_user\"}")
                .on("GET", "/api/v1/accounts/verify_credentials", HttpStatus.OK,
                        "{\"id\":\"1\",\"username\":\"" + MASTODON_LP + "\",\"display_name\":\"" + displayName + "\"}")
                .on("PATCH", "/api/v1/accounts/update_credentials", HttpStatus.OK, "{}");
    }

    @Test
    void mastodon_emptyDisplayName_isSetToTheUsername() {
        Homeserver hs = mastodonRecover("");

        StepVerifier.create(broker(hs, name("e2e-matrix")).mintMastodon("casdoor:" + UUID, MASTODON_LP))
                .assertNext(t -> assertThat(t.accessToken()).isEqualTo("mst_user"))
                .verifyComplete();

        assertThat(hs.writes()).hasSize(1);
        assertThat(hs.writes().get(0).rawPath()).isEqualTo("/api/v1/accounts/update_credentials");
        assertThat(hs.writes().get(0).body()).isEqualTo("{\"display_name\":\"e2e-matrix\"}");
    }

    @Test
    void mastodon_registerLeg_akkomaNicknameDefault_isSetToTheUsername() {
        // Password grant refused -> client_credentials -> POST /api/v1/accounts (user token);
        // Akkoma fills name = nickname when registration carries none.
        Homeserver hs = new Homeserver()
                .on("POST", "/api/v1/apps", HttpStatus.OK, "{\"client_id\":\"cid\",\"client_secret\":\"cs\"}")
                .on("POST", "/oauth/token", HttpStatus.BAD_REQUEST, "{\"error\":\"invalid_grant\"}")
                .on("POST", "/oauth/token", HttpStatus.OK, "{\"access_token\":\"app_tok\"}")
                .on("POST", "/api/v1/accounts", HttpStatus.OK, "{\"access_token\":\"mst_new\"}")
                .on("GET", "/api/v1/accounts/verify_credentials", HttpStatus.OK,
                        "{\"username\":\"" + MASTODON_LP + "\",\"display_name\":\"" + MASTODON_LP + "\"}")
                .on("PATCH", "/api/v1/accounts/update_credentials", HttpStatus.OK, "{}");

        StepVerifier.create(broker(hs, name("e2e-matrix")).mintMastodon("casdoor:" + UUID, MASTODON_LP))
                .assertNext(t -> assertThat(t.accessToken()).isEqualTo("mst_new"))
                .verifyComplete();

        assertThat(hs.writes()).extracting(Seen::body).containsExactly("{\"display_name\":\"e2e-matrix\"}");
    }

    @Test
    void mastodon_chosenNameKept_unknownNameSkipped_failuresSwallowed() {
        Homeserver chosen = mastodonRecover("Someone Real");
        StepVerifier.create(broker(chosen, name("e2e-matrix")).mintMastodon("o", MASTODON_LP))
                .expectNextCount(1).verifyComplete();
        assertThat(chosen.writes()).isEmpty();

        Homeserver unknown = mastodonRecover("");
        StepVerifier.create(broker(unknown, name("")).mintMastodon("o", MASTODON_LP))
                .expectNextCount(1).verifyComplete();
        assertThat(unknown.seen).extracting(Seen::rawPath)
                .doesNotContain("/api/v1/accounts/verify_credentials");

        // Mainline Mastodon answers 403 for an account still awaiting e-mail confirmation.
        Homeserver unconfirmed = new Homeserver()
                .on("POST", "/api/v1/apps", HttpStatus.OK, "{\"client_id\":\"cid\",\"client_secret\":\"cs\"}")
                .on("POST", "/oauth/token", HttpStatus.OK, "{\"access_token\":\"mst_user\"}")
                .on("GET", "/api/v1/accounts/verify_credentials", HttpStatus.FORBIDDEN,
                        "{\"error\":\"Your login is missing a confirmed e-mail address\"}");
        StepVerifier.create(broker(unconfirmed, name("e2e-matrix")).mintMastodon("o", MASTODON_LP))
                .assertNext(t -> assertThat(t.accessToken()).isEqualTo("mst_user"))
                .verifyComplete();
    }

    // ── A name the person CHOSE in their user-bff profile ───────────────────────

    @Test
    void chosenName_overwritesTheHomeserverName_onAccountsAlreadyInCustody() {
        when(custody.loadAccessToken("casdoor:" + UUID, HsServiceTokenRow.PLATFORM_MATRIX))
                .thenReturn(Mono.just("syt_held"));
        when(custody.loadAccessToken("casdoor:" + UUID, HsServiceTokenRow.PLATFORM_MASTODON))
                .thenReturn(Mono.just("mst_held"));
        Homeserver hs = new Homeserver()
                .on("GET", "/_matrix/client/v3/account/whoami", HttpStatus.OK, "{\"user_id\":\"" + MXID + "\"}")
                .on("GET", PROFILE_PATH, HttpStatus.OK, "{\"displayname\":\"e2e-matrix\"}")
                .on("PUT", PROFILE_PATH, HttpStatus.OK, "{}")
                .on("GET", "/api/v1/accounts/verify_credentials", HttpStatus.OK,
                        "{\"username\":\"" + MASTODON_LP + "\",\"display_name\":\"e2e-matrix\"}")
                .on("PATCH", "/api/v1/accounts/update_credentials", HttpStatus.OK, "{}");

        StepVerifier.create(broker(hs, name("e2e-matrix")).pushChosenDisplayName("casdoor:" + UUID, "Matrix Tester"))
                .verifyComplete();

        assertThat(hs.writes()).extracting(Seen::body).containsExactlyInAnyOrder(
                "{\"displayname\":\"Matrix Tester\"}", "{\"display_name\":\"Matrix Tester\"}");
    }

    @Test
    void chosenName_unchanged_orNoCustodyToken_writesNothing_andNeverMints() {
        when(custody.loadAccessToken("o", HsServiceTokenRow.PLATFORM_MATRIX)).thenReturn(Mono.just("syt_held"));
        when(custody.loadAccessToken("o", HsServiceTokenRow.PLATFORM_MASTODON)).thenReturn(Mono.empty());
        Homeserver hs = new Homeserver()
                .on("GET", "/_matrix/client/v3/account/whoami", HttpStatus.OK, "{\"user_id\":\"" + MXID + "\"}")
                .on("GET", PROFILE_PATH, HttpStatus.OK, "{\"displayname\":\"Matrix Tester\"}");

        StepVerifier.create(broker(hs, name("")).pushChosenDisplayName("o", "Matrix Tester")).verifyComplete();

        assertThat(hs.writes()).isEmpty();
        assertThat(hs.seen).extracting(Seen::rawPath)
                .doesNotContain("/_matrix/client/v3/register", "/oauth/token", "/api/v1/apps");
    }

    @Test
    void chosenName_homeserverDown_completesQuietly() {
        when(custody.loadAccessToken("o", HsServiceTokenRow.PLATFORM_MATRIX)).thenReturn(Mono.just("syt_held"));
        when(custody.loadAccessToken("o", HsServiceTokenRow.PLATFORM_MASTODON))
                .thenReturn(Mono.error(new IllegalStateException("custody key missing")));
        Homeserver hs = new Homeserver()
                .on("GET", "/_matrix/client/v3/account/whoami", HttpStatus.BAD_GATEWAY, "{}");

        StepVerifier.create(broker(hs, name("")).pushChosenDisplayName("o", "Matrix Tester")).verifyComplete();
        StepVerifier.create(broker(hs, name("")).pushChosenDisplayName("o", "  ")).verifyComplete();
    }

    @Test
    void mastodon_longNamesAreCutToMastodonsThirtyCharacterLimit() {
        assertThat(ServiceTokenBroker.truncateForMastodon("a".repeat(40))).hasSize(30);
        assertThat(ServiceTokenBroker.truncateForMastodon("short")).isEqualTo("short");
        // Never splits a surrogate pair.
        String emoji = "💕".repeat(31);
        assertThat(ServiceTokenBroker.truncateForMastodon(emoji).codePointCount(0,
                ServiceTokenBroker.truncateForMastodon(emoji).length())).isEqualTo(30);
        assertThat(ServiceTokenBroker.cleanDisplayName("  e2e-matrix ")).isEqualTo("e2e-matrix");
        assertThat(ServiceTokenBroker.cleanDisplayName("evil\u0000name")).isEmpty();
    }
}
