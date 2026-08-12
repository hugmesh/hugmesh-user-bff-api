package net.hugmesh.userbff.character;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies {@link MatrixClientApiClient} — the generic per-user Matrix client-server
 * account-data client (the GET + PUT legs of the MSC2545 read-modify-write) — against a
 * recording {@link ExchangeFunction} stub (no live homeserver):
 * <ul>
 *   <li>STUB mode (null WebClient — the dark default): NO HTTP — GET resolves EMPTY (no
 *       existing pack) and PUT completes without a call;</li>
 *   <li>LIVE GET 200: parses the JSON body into a generic map and forwards the per-call
 *       bearer (never a default header);</li>
 *   <li>LIVE GET 404: maps to EMPTY (the first-pack case), no throw;</li>
 *   <li>LIVE PUT: issues a PUT with the JSON body and the per-call bearer.</li>
 * </ul>
 */
class MatrixClientApiClientTest {

    private static final String USER_ID = "@alice:hs";
    private static final String TYPE = "im.ponies.user_emotes";
    private static final String TOKEN = "syt_secret_token";

    /** A recording exchange that answers with a fixed status + body and captures requests. */
    static class Recorder implements ExchangeFunction {
        final List<ClientRequest> requests = new ArrayList<>();
        private final HttpStatus status;
        private final String body;

        Recorder(HttpStatus status, String body) {
            this.status = status;
            this.body = body;
        }

        @Override
        public Mono<ClientResponse> exchange(ClientRequest request) {
            requests.add(request);
            ClientResponse.Builder b = ClientResponse.create(status)
                    .header("Content-Type", "application/json");
            return Mono.just(b.body(body == null ? "" : body).build());
        }

        ClientRequest first() {
            return requests.get(0);
        }
    }

    private static MatrixClientApiClient liveClient(Recorder rec) {
        return new MatrixClientApiClient(WebClient.builder().exchangeFunction(rec).build());
    }

    // ── STUB (dark) mode ────────────────────────────────────────────────────────

    @Test
    void stub_get_isEmpty_noHttp() {
        MatrixClientApiClient stub = new MatrixClientApiClient(null);
        assertThat(stub.isLive()).isFalse();
        StepVerifier.create(stub.getAccountData(USER_ID, TYPE, TOKEN)).verifyComplete();
    }

    @Test
    void stub_set_completes_noHttp() {
        MatrixClientApiClient stub = new MatrixClientApiClient(null);
        StepVerifier.create(stub.setAccountData(USER_ID, TYPE, Map.of("a", "b"), TOKEN)).verifyComplete();
    }

    // ── LIVE GET ────────────────────────────────────────────────────────────────

    @Test
    void liveGet_200_parsesBody_forwardsBearer() {
        Recorder rec = new Recorder(HttpStatus.OK, "{\"images\":{\"happy\":{\"url\":\"mxc://h/1\"}}}");
        MatrixClientApiClient live = liveClient(rec);

        Map<String, Object> body = live.getAccountData(USER_ID, TYPE, TOKEN).block();

        assertThat(body).containsKey("images");
        ClientRequest req = rec.first();
        assertThat(req.method()).isEqualTo(HttpMethod.GET);
        assertThat(req.url().getPath()).contains("/_matrix/client/v3/user/").contains("account_data");
        assertThat(req.headers().getFirst(HttpHeaders.AUTHORIZATION)).isEqualTo("Bearer " + TOKEN);
    }

    @Test
    void liveGet_404_isEmpty_firstPackCase() {
        Recorder rec = new Recorder(HttpStatus.NOT_FOUND, "{\"errcode\":\"M_NOT_FOUND\"}");
        MatrixClientApiClient live = liveClient(rec);

        StepVerifier.create(live.getAccountData(USER_ID, TYPE, TOKEN)).verifyComplete();
    }

    // ── LIVE PUT ────────────────────────────────────────────────────────────────

    @Test
    void livePut_issuesPut_withBearer() {
        Recorder rec = new Recorder(HttpStatus.OK, "{}");
        MatrixClientApiClient live = liveClient(rec);

        StepVerifier.create(live.setAccountData(USER_ID, TYPE, Map.of("pack", Map.of("k", "v")), TOKEN))
                .verifyComplete();

        ClientRequest req = rec.first();
        assertThat(req.method()).isEqualTo(HttpMethod.PUT);
        assertThat(req.url().getPath()).contains("/_matrix/client/v3/user/").contains("account_data");
        assertThat(req.headers().getFirst(HttpHeaders.AUTHORIZATION)).isEqualTo("Bearer " + TOKEN);
    }
}
