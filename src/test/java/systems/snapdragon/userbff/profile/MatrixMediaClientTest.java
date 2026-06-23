package systems.snapdragon.userbff.profile;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies {@link MatrixMediaClient} in both modes against a recording
 * {@link ExchangeFunction} stub:
 * <ul>
 *   <li>STUB mode (null WebClient — the default) — no HTTP call is made and
 *       {@code upload(...)} resolves to a DETERMINISTIC {@code mxc://stub.invalid/...}
 *       (stable per owner) so avatar storage works while the feature ships dark;</li>
 *   <li>LIVE mode — a POST is issued to the homeserver media-upload path and the
 *       returned {@code content_uri} is parsed back as the mxc:// URL.</li>
 * </ul>
 */
class MatrixMediaClientTest {

    static class Recorder implements ExchangeFunction {
        final List<ClientRequest> requests = new ArrayList<>();
        @Override public Mono<ClientResponse> exchange(ClientRequest request) {
            requests.add(request);
            return Mono.just(ClientResponse.create(HttpStatus.OK)
                    .header("Content-Type", "application/json")
                    .body("{\"content_uri\":\"mxc://home/uploaded123\"}").build());
        }
        boolean hitContains(String frag) {
            return requests.stream().anyMatch(r -> r.url().getPath().contains(frag));
        }
    }

    @Test
    void stub_noHttp_returnsDeterministicStubMxc() {
        MatrixMediaClient stub = new MatrixMediaClient(null);
        String mxc = stub.upload("alice", new byte[]{1, 2, 3}, "image/png").block();
        assertThat(mxc).startsWith("mxc://stub.invalid/");
        // deterministic: same owner -> same stub mxc (predictable reads in dark mode)
        String again = stub.upload("alice", new byte[]{9}, "image/jpeg").block();
        assertThat(again).isEqualTo(mxc);
        // different owner -> different stub mxc
        String other = stub.upload("bob", new byte[]{1}, "image/png").block();
        assertThat(other).isNotEqualTo(mxc);
    }

    @Test
    void live_postsBytes_parsesContentUri() {
        Recorder rec = new Recorder();
        MatrixMediaClient live = new MatrixMediaClient(WebClient.builder().exchangeFunction(rec).build());
        String mxc = live.upload("@alice:home", new byte[]{1, 2, 3}, "image/png").block();
        assertThat(mxc).isEqualTo("mxc://home/uploaded123");
        assertThat(rec.requests.get(0).method()).isEqualTo(HttpMethod.POST);
        assertThat(rec.hitContains("/_matrix/media/v1/upload")).isTrue();
    }
}
