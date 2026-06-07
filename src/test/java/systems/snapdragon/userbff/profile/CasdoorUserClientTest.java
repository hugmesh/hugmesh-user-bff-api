package systems.snapdragon.userbff.profile;

import org.junit.jupiter.api.Test;
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
 * Verifies the {@link CasdoorUserClient}: in LIVE mode it issues the documented
 * set-password / update-user(email) calls (recording {@link ExchangeFunction}
 * stub); in STUB mode (null WebClient) it makes no HTTP call but the reactive flow
 * still completes. The exact Casdoor payload is version-specific and validated
 * against a running casdoor-all-in-one (see README), not in CI.
 */
class CasdoorUserClientTest {

    static class Recorder implements ExchangeFunction {
        final List<ClientRequest> requests = new ArrayList<>();
        @Override public Mono<ClientResponse> exchange(ClientRequest request) {
            requests.add(request);
            return Mono.just(ClientResponse.create(HttpStatus.OK)
                    .header("Content-Type", "application/json").body("{\"status\":\"ok\"}").build());
        }
        boolean hit(String suffix) { return requests.stream().anyMatch(r -> r.url().getPath().endsWith(suffix)); }
    }

    private CasdoorUserClient live(Recorder rec) {
        return new CasdoorUserClient(WebClient.builder().exchangeFunction(rec).build(), "snapdragon");
    }

    @Test
    void live_changePassword_callsSetPassword() {
        Recorder rec = new Recorder();
        live(rec).changePassword("alice", "old", "new").block();
        assertThat(rec.hit("/api/set-password")).isTrue();
    }

    @Test
    void live_changeEmail_callsUpdateUser() {
        Recorder rec = new Recorder();
        live(rec).changeEmail("alice", "new@x.com").block();
        assertThat(rec.hit("/api/update-user")).isTrue();
        assertThat(rec.requests.get(0).url().getQuery()).contains("id=snapdragon/alice");
    }

    @Test
    void stub_noHttpButCompletes() {
        CasdoorUserClient stub = new CasdoorUserClient(null, "snapdragon");
        assertThat(stub.enabled()).isFalse();
        // completes empty without throwing
        stub.changePassword("alice", "old", "new").block();
        stub.changeEmail("alice", "new@x.com").block();
    }
}
