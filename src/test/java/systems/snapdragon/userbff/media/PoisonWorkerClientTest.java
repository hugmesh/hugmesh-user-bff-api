package systems.snapdragon.userbff.media;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import systems.snapdragon.userbff.media.PoisonModels.Health;
import systems.snapdragon.userbff.media.PoisonModels.PoisonResult;
import systems.snapdragon.userbff.media.PoisonModels.SurvivalVerdict;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies the {@link PoisonWorkerClient} against a recording {@link ExchangeFunction}
 * stub (no live worker): the documented /health, /poison, /survival shapes; AND that a
 * null WebClient (no worker wired) degrades to "absent" without any HTTP — the lean
 * fallback trigger. Mirrors FederationApiClientTest / ExternalBlockClientTest.
 */
class PoisonWorkerClientTest {

    static class Recorder implements ExchangeFunction {
        final List<ClientRequest> requests = new ArrayList<>();
        @Override public Mono<ClientResponse> exchange(ClientRequest request) {
            requests.add(request);
            String path = request.url().getPath();
            String body;
            if (path.endsWith("/health")) {
                body = "{\"backend\":\"cuda\",\"modes\":[\"glaze\",\"nightshade\"],\"etaSeconds\":60}";
            } else if (path.endsWith("/poison")) {
                body = "{\"ok\":true,\"backend\":\"cuda\",\"poisonedOriginal\":\"" + b64("CLOAKED")
                        + "\",\"thumbnails\":[{\"size\":\"small\",\"bytes\":\"" + b64("SMALL") + "\"}]}";
            } else { // /survival
                body = "{\"present\":true,\"score\":0.92}";
            }
            return Mono.just(ClientResponse.create(HttpStatus.OK)
                    .header("Content-Type", "application/json").body(body).build());
        }
        ClientRequest last() { return requests.get(requests.size() - 1); }
        boolean hit(String suffix) { return requests.stream().anyMatch(r -> r.url().getPath().endsWith(suffix)); }
    }

    private static String b64(String s) {
        return java.util.Base64.getEncoder().encodeToString(s.getBytes());
    }

    private PoisonWorkerClient clientFor(Recorder rec) {
        WebClient web = WebClient.builder().exchangeFunction(rec).build();
        return new PoisonWorkerClient(web, Duration.ofSeconds(2), Duration.ofSeconds(30));
    }

    @Test
    void capability_getsHealth_backendCuda() {
        Recorder rec = new Recorder();
        Health h = clientFor(rec).capability().block();
        assertThat(rec.hit("/health")).isTrue();
        assertThat(h.backend()).isEqualTo("cuda");
        assertThat(h.modes()).contains("glaze", "nightshade");
        assertThat(h.etaSeconds()).isEqualTo(60);
    }

    @Test
    void poison_postsOriginal_withModeAndSizes() {
        Recorder rec = new Recorder();
        PoisonResult r = clientFor(rec)
                .poison("ORIG".getBytes(), "glaze", "a.png", "image/png", List.of("small", "240x240"))
                .block();
        assertThat(rec.last().url().getPath()).endsWith("/poison");
        assertThat(rec.last().headers().getFirst("X-Cloak-Mode")).isEqualTo("glaze");
        assertThat(rec.last().headers().getFirst("X-Cloak-Thumbnail-Sizes")).isEqualTo("small,240x240");
        assertThat(r).isNotNull();
        assertThat(r.ok()).isTrue();
        assertThat(r.backend()).isEqualTo("cuda");
        assertThat(new String(r.poisonedOriginal())).isEqualTo("CLOAKED");
        assertThat(r.thumbnails()).hasSize(1);
    }

    @Test
    void checkSurvival_postsServedBytes_presentTrue() {
        Recorder rec = new Recorder();
        SurvivalVerdict v = clientFor(rec)
                .checkSurvival("SERVED".getBytes(), "glaze", "original").block();
        assertThat(rec.last().url().getPath()).endsWith("/survival");
        assertThat(rec.last().headers().getFirst("X-Cloak-Size")).isEqualTo("original");
        assertThat(v.present()).isTrue();
    }

    @Test
    void nullWorker_capabilityAbsent_noHttp() {
        PoisonWorkerClient absent = new PoisonWorkerClient(null,
                Duration.ofSeconds(2), Duration.ofSeconds(30));
        Health h = absent.capability().block();
        assertThat(h.backend()).isEqualTo("none");
        assertThat(PoisonModels.Backend.parse(h.backend()).present()).isFalse();
    }

    @Test
    void nullWorker_poisonEmpty_survivalNotPresent() {
        PoisonWorkerClient absent = new PoisonWorkerClient(null,
                Duration.ofSeconds(2), Duration.ofSeconds(30));
        assertThat(absent.poison("x".getBytes(), "glaze", "a", "image/png", List.of()).blockOptional()).isEmpty();
        assertThat(absent.checkSurvival("x".getBytes(), "glaze", "original").block().present()).isFalse();
    }

    @Test
    void capability_onError_degradesToAbsent() {
        // an exchange that errors (e.g. connect refused) resolves to backend=none.
        ExchangeFunction boom = req -> Mono.error(new RuntimeException("connect refused"));
        PoisonWorkerClient c = new PoisonWorkerClient(
                WebClient.builder().exchangeFunction(boom).build(),
                Duration.ofSeconds(2), Duration.ofSeconds(30));
        assertThat(c.capability().block().backend()).isEqualTo("none");
    }
}
