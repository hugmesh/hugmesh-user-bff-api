package systems.snapdragon.userbff.auth;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import systems.snapdragon.userbff.federation.FederationHttpClientSsl;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@link AdminBffInternalClient} + {@link AdminBffInternalConfig} behaviour, driven by
 * a recording {@link ExchangeFunction} stub (no live admin-bff). Proves:
 * <ul>
 *   <li>the live client stamps {@code X-Internal-Token} on its calls when the config
 *       supplies a non-blank token, and issues the documented admin-bff #112 request
 *       shapes;</li>
 *   <li>the DISABLED client ({@code app.bff.oidc.enabled=false}) is a fail-closed stub —
 *       {@code enabled()==false} and every method errors, never silently succeeds;</li>
 *   <li>the mTLS connector is applied to the live client when
 *       {@code snapdragon.mtls.client.enabled} (via the shared FederationHttpClientSsl).</li>
 * </ul>
 */
class AdminBffInternalClientTest {

    /** Records outbound requests and replies with a canned account/session JSON. */
    static class Recorder implements ExchangeFunction {
        final List<ClientRequest> requests = new ArrayList<>();

        @Override
        public Mono<ClientResponse> exchange(ClientRequest request) {
            requests.add(request);
            String path = request.url().getPath();
            if (path.endsWith("/sessions")) {
                return Mono.just(ClientResponse.create(HttpStatus.OK)
                        .header("Content-Type", "application/json")
                        .body("{\"token\":\"bff_opaque\",\"accountId\":\"acc-1\"}").build());
            }
            if (path.endsWith("/custody/stamp")) {
                return Mono.just(ClientResponse.create(HttpStatus.NO_CONTENT).build());
            }
            if (path.endsWith("/session/introspect")) {
                // admin-bff IntrospectResponse shape (no handle — resolved from the account view).
                return Mono.just(ClientResponse.create(HttpStatus.OK)
                        .header("Content-Type", "application/json")
                        .body("{\"id\":\"acc-1\",\"provider\":\"casdoor\",\"roles\":[\"user\"],"
                                + "\"registrationComplete\":false,\"status\":\"active\","
                                + "\"mfaSatisfied\":false}").build());
            }
            if (path.endsWith("/session/exchange")) {
                // admin-bff exchange response shape: {"bearer": <custody JWT>}.
                return Mono.just(ClientResponse.create(HttpStatus.OK)
                        .header("Content-Type", "application/json")
                        .body("{\"bearer\":\"custody-jwt-xyz\"}").build());
            }
            // accounts/ensure (and getAccount/complete) -> an account view. localpart is the
            // account-takeover-by-collision fix's persisted, collision-checked homeserver
            // username (Liquibase changeset 290 on admin-bff) — DELIBERATELY distinct from
            // "alice" (the handle) to prove the client surfaces the field admin-bff actually
            // sent, not a re-derivation of the handle.
            return Mono.just(ClientResponse.create(HttpStatus.OK)
                    .header("Content-Type", "application/json")
                    .body("{\"id\":\"acc-1\",\"provider\":\"casdoor\",\"handle\":\"alice\","
                            + "\"registrationComplete\":false,\"roles\":[\"user\"],"
                            + "\"localpart\":\"alice-canonical\"}").build());
        }
    }

    private static AdminBffInternalClient liveClient(Recorder recorder, String internalToken) {
        WebClient.Builder builder = WebClient.builder()
                .baseUrl("http://admin-bff.test")
                .exchangeFunction(recorder);
        if (internalToken != null && !internalToken.isBlank()) {
            builder.defaultHeader("X-Internal-Token", internalToken);
        }
        return new AdminBffInternalClient(builder.build());
    }

    @Test
    void liveClient_stampsInternalToken_andEnsuresAccount() {
        Recorder recorder = new Recorder();
        AdminBffInternalClient client = liveClient(recorder, "s3cr3t-internal");

        StepVerifier.create(client.ensureAccount("casdoor", "alice"))
                .assertNext(a -> {
                    assertThat(a.id()).isEqualTo("acc-1");
                    assertThat(a.provider()).isEqualTo("casdoor");
                    // Account-takeover-by-collision fix: the CANONICAL localpart admin-bff
                    // persisted, not a re-derivation of the handle.
                    assertThat(a.localpart()).isEqualTo("alice-canonical");
                })
                .verifyComplete();

        assertThat(client.enabled()).isTrue();
        assertThat(recorder.requests).hasSize(1);
        ClientRequest req = recorder.requests.get(0);
        assertThat(req.url().getPath()).isEqualTo("/bff/internal/accounts/ensure");
        assertThat(req.headers().getFirst("X-Internal-Token")).isEqualTo("s3cr3t-internal");
    }

    @Test
    void liveClient_exchangeSession_swapsBffTokenForCustodyBearer() {
        Recorder recorder = new Recorder();
        AdminBffInternalClient client = liveClient(recorder, "s3cr3t-internal");

        StepVerifier.create(client.exchangeSession("bff_opaque"))
                .assertNext(bearer -> assertThat(bearer).isEqualTo("custody-jwt-xyz"))
                .verifyComplete();

        ClientRequest req = recorder.requests.get(0);
        assertThat(req.url().getPath()).isEqualTo("/bff/internal/session/exchange");
        assertThat(req.method().name()).isEqualTo("POST");
        assertThat(req.headers().getFirst("X-Internal-Token")).isEqualTo("s3cr3t-internal");
    }

    @Test
    void disabledClient_exchangeSession_failsClosed() {
        AdminBffInternalClient stub = new AdminBffInternalClient(null);
        assertThat(stub.enabled()).isFalse();
        StepVerifier.create(stub.exchangeSession("bff_x"))
                .expectError(IllegalStateException.class)
                .verify();
    }

    @Test
    void liveClient_exchangeSession_blankBearer_errors() {
        // A 2xx body with no usable bearer must NOT resolve to a forwardable value.
        ExchangeFunction blankBearer = request -> Mono.just(ClientResponse.create(HttpStatus.OK)
                .header("Content-Type", "application/json").body("{\"bearer\":\"\"}").build());
        AdminBffInternalClient client = new AdminBffInternalClient(
                WebClient.builder().baseUrl("http://admin-bff.test").exchangeFunction(blankBearer).build());
        StepVerifier.create(client.exchangeSession("bff_x"))
                .expectError(IllegalStateException.class)
                .verify();
    }

    @Test
    void liveClient_createSession_returnsOpaqueToken() {
        Recorder recorder = new Recorder();
        AdminBffInternalClient client = liveClient(recorder, "s3cr3t-internal");

        StepVerifier.create(client.createSession("acc-1"))
                .assertNext(s -> assertThat(s.token()).isEqualTo("bff_opaque"))
                .verifyComplete();
        assertThat(recorder.requests.get(0).url().getPath()).isEqualTo("/bff/internal/sessions");
    }

    @Test
    void liveClient_getAccountBySession_introspectsThenFetchesAccountById() {
        // A bff_ session token is resolved in TWO hops: introspect the session -> account id,
        // then fetch the full account view by that id (regression guard for the old bug that
        // passed the session token straight to GET /accounts/{id}, which 404'd).
        Recorder recorder = new Recorder();
        AdminBffInternalClient client = liveClient(recorder, "s3cr3t-internal");

        StepVerifier.create(client.getAccountBySession("bff_opaque"))
                .assertNext(a -> {
                    assertThat(a.id()).isEqualTo("acc-1");
                    assertThat(a.handle()).isEqualTo("alice");   // from the account view, not introspect
                })
                .verifyComplete();

        assertThat(recorder.requests).hasSize(2);
        assertThat(recorder.requests.get(0).url().getPath()).isEqualTo("/bff/internal/session/introspect");
        assertThat(recorder.requests.get(0).headers().getFirst(HttpHeaders.AUTHORIZATION))
                .isEqualTo("Bearer bff_opaque");
        // The SECOND call resolves the account by the introspected id, NEVER by the raw token.
        assertThat(recorder.requests.get(1).url().getPath()).isEqualTo("/bff/internal/accounts/acc-1");
    }

    @Test
    void liveClient_getAccountBySession_unknownSession_mapsTo401() {
        // admin-bff introspect returns 401 for an unknown/expired session — the client must
        // surface a 401 ResponseStatusException (so /me + /session return "no session"), NOT
        // let the raw WebClientResponseException bubble to a 500. The account fetch never runs.
        List<ClientRequest> seen = new ArrayList<>();
        ExchangeFunction unauthorized = req -> {
            seen.add(req);
            return Mono.just(ClientResponse.create(HttpStatus.UNAUTHORIZED).build());
        };
        AdminBffInternalClient client = new AdminBffInternalClient(
                WebClient.builder().baseUrl("http://admin-bff.test").exchangeFunction(unauthorized).build());

        StepVerifier.create(client.getAccountBySession("bff_stale"))
                .expectErrorSatisfies(e -> {
                    assertThat(e).isInstanceOf(ResponseStatusException.class);
                    assertThat(((ResponseStatusException) e).getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
                })
                .verify();

        // Only the introspect call was made; the account-by-id fetch is short-circuited.
        assertThat(seen).hasSize(1);
        assertThat(seen.get(0).url().getPath()).isEqualTo("/bff/internal/session/introspect");
    }

    @Test
    void liveClient_stampCustody_postsCiphertext() {
        Recorder recorder = new Recorder();
        AdminBffInternalClient client = liveClient(recorder, "s3cr3t-internal");

        StepVerifier.create(client.stampCustody("bff_opaque", "enc-a", "enc-r", 3600L))
                .verifyComplete();
        assertThat(recorder.requests.get(0).url().getPath()).isEqualTo("/bff/internal/custody/stamp");
    }

    @Test
    void liveClient_stampCustody_nullRefresh_doesNotThrow() {
        // Casdoor may return OidcTokens with no refresh_token ⇒ encRefresh is null.
        // The request body must tolerate it (Map.of would NPE) and complete normally.
        Recorder recorder = new Recorder();
        AdminBffInternalClient client = liveClient(recorder, "s3cr3t-internal");

        StepVerifier.create(client.stampCustody("bff_opaque", "enc-a", null, 3600L))
                .verifyComplete();
        assertThat(recorder.requests.get(0).url().getPath()).isEqualTo("/bff/internal/custody/stamp");
    }

    @Test
    void noInternalToken_noStamp() {
        Recorder recorder = new Recorder();
        AdminBffInternalClient client = liveClient(recorder, "");

        client.ensureAccount("casdoor", "alice").block();
        assertThat(recorder.requests.get(0).headers().getFirst("X-Internal-Token")).isNull();
    }

    @Test
    void disabledClient_isFailClosedStub() {
        // Built exactly as AdminBffInternalConfig does when app.bff.oidc.enabled=false.
        AdminBffInternalConfig config = new AdminBffInternalConfig();
        AdminBffInternalClient client = config.adminBffInternalClient(
                new FederationHttpClientSsl(), /*oidcEnabled*/ false,
                "http://admin-bff.test", "X-Internal-Token", "");

        assertThat(client.enabled()).isFalse();
        // Every op errors (fail closed) — never a silent success.
        StepVerifier.create(client.ensureAccount("casdoor", "alice"))
                .verifyError(IllegalStateException.class);
        StepVerifier.create(client.createSession("acc-1"))
                .verifyError(IllegalStateException.class);
        StepVerifier.create(client.getAccountBySession("bff_opaque"))
                .verifyError(IllegalStateException.class);
        StepVerifier.create(client.stampCustody("t", "a", "r", 1L))
                .verifyError(IllegalStateException.class);
        StepVerifier.create(client.allowlistCheck("casdoor", "alice"))
                .verifyError(IllegalStateException.class);
    }

    @Test
    void accountView_missingLocalpartField_defaultsToBlank_notNull() {
        // A row that predates the account.localpart column (or an admin-bff version skew)
        // omits the field entirely; the accessor must default to "" (never null and never
        // silently fall back to some OTHER field), so a blank check is always safe for a
        // caller that must treat "unset" as "resolve it", not NPE or misread a stale handle.
        ExchangeFunction noLocalpartField = req -> Mono.just(ClientResponse.create(HttpStatus.OK)
                .header("Content-Type", "application/json")
                .body("{\"id\":\"acc-1\",\"provider\":\"casdoor\",\"handle\":\"alice\","
                        + "\"registrationComplete\":false,\"roles\":[\"user\"]}").build());
        AdminBffInternalClient client = new AdminBffInternalClient(
                WebClient.builder().baseUrl("http://admin-bff.test").exchangeFunction(noLocalpartField).build());

        StepVerifier.create(client.ensureAccount("casdoor", "alice"))
                .assertNext(a -> assertThat(a.localpart()).isEqualTo(""))
                .verifyComplete();
    }

    @Test
    void config_whenEnabled_buildsLiveClient_andAppliesMtlsConnector() {
        // mtls.enabled=true but no keystore file present ⇒ FederationHttpClientSsl
        // degrades to the default connector (shouldApply()==false) rather than throwing,
        // so the live client still builds. The point is the config takes the live branch.
        FederationHttpClientSsl mtls = new FederationHttpClientSsl();
        mtls.setEnabled(true);
        mtls.setKeyStore("/nonexistent/keystore.p12");

        AdminBffInternalConfig config = new AdminBffInternalConfig();
        AdminBffInternalClient client = config.adminBffInternalClient(
                mtls, /*oidcEnabled*/ true,
                "http://admin-bff.test", "X-Internal-Token", "s3cr3t-internal");

        assertThat(client.enabled()).isTrue();
    }
}
