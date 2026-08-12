package net.hugmesh.userbff.block;

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
 * Verifies the external self-block clients against a recording
 * {@link ExchangeFunction} stub: in LIVE mode the Matrix ignore-list PUT and the
 * Mastodon lookup+block POST are issued with the documented shapes; in STUB mode
 * (null WebClient — the default) no HTTP call is made and {@code block(...)}
 * resolves to {@code false} so the durable user_block row remains the source of
 * truth. The exact external payloads + per-user token brokering are validated out
 * of band (see README deferrals).
 */
class ExternalBlockClientTest {

    static class Recorder implements ExchangeFunction {
        final List<ClientRequest> requests = new ArrayList<>();
        String lookupJson = "{\"id\":\"42\"}";
        @Override public Mono<ClientResponse> exchange(ClientRequest request) {
            requests.add(request);
            String body = request.url().getPath().contains("/lookup") ? lookupJson : "{}";
            return Mono.just(ClientResponse.create(HttpStatus.OK)
                    .header("Content-Type", "application/json").body(body).build());
        }
        boolean hit(String suffix) { return requests.stream().anyMatch(r -> r.url().getPath().endsWith(suffix)); }
        boolean hitContains(String frag) { return requests.stream().anyMatch(r -> r.url().getPath().contains(frag)); }
    }

    @Test
    void matrix_stub_noHttp_returnsFalse() {
        MatrixBlockClient stub = new MatrixBlockClient(null);
        assertThat(stub.platform()).isEqualTo("matrix");
        assertThat(stub.block("alice", "@x:evil").block()).isFalse();
    }

    @Test
    void matrix_live_putsIgnoredUserList() {
        Recorder rec = new Recorder();
        MatrixBlockClient live = new MatrixBlockClient(WebClient.builder().exchangeFunction(rec).build());
        Boolean pushed = live.block("@alice:home", "@spammer:evil").block();
        assertThat(pushed).isTrue();
        assertThat(rec.requests.get(0).method()).isEqualTo(HttpMethod.PUT);
        assertThat(rec.hit("/account_data/m.ignored_user_list")).isTrue();
    }

    @Test
    void mastodon_stub_noHttp_returnsFalse() {
        MastodonBlockClient stub = new MastodonBlockClient(null);
        assertThat(stub.platform()).isEqualTo("mastodon");
        assertThat(stub.block("alice", "spammer@evil").block()).isFalse();
    }

    @Test
    void mastodon_live_looksUpThenBlocks() {
        Recorder rec = new Recorder();
        MastodonBlockClient live = new MastodonBlockClient(WebClient.builder().exchangeFunction(rec).build());
        Boolean pushed = live.block("alice", "spammer@evil").block();
        assertThat(pushed).isTrue();
        assertThat(rec.hitContains("/api/v1/accounts/lookup")).isTrue();
        assertThat(rec.hit("/api/v1/accounts/42/block")).isTrue();
    }
}
