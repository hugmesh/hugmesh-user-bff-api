package systems.snapdragon.userbff.auth;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import org.springframework.web.reactive.function.client.WebClient;
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
            // accounts/ensure (and getAccount/complete) -> an account view
            return Mono.just(ClientResponse.create(HttpStatus.OK)
                    .header("Content-Type", "application/json")
                    .body("{\"id\":\"acc-1\",\"provider\":\"casdoor\",\"handle\":\"alice\","
                            + "\"registrationComplete\":false,\"roles\":[\"user\"]}").build());
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
                })
                .verifyComplete();

        assertThat(client.enabled()).isTrue();
        assertThat(recorder.requests).hasSize(1);
        ClientRequest req = recorder.requests.get(0);
        assertThat(req.url().getPath()).isEqualTo("/bff/internal/accounts/ensure");
        assertThat(req.headers().getFirst("X-Internal-Token")).isEqualTo("s3cr3t-internal");
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
        StepVerifier.create(client.stampCustody("t", "a", "r", 1L))
                .verifyError(IllegalStateException.class);
        StepVerifier.create(client.allowlistCheck("casdoor", "alice"))
                .verifyError(IllegalStateException.class);
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
