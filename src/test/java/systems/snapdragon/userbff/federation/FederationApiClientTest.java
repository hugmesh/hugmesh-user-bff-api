package systems.snapdragon.userbff.federation;

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
 * Verifies the {@link FederationApiClient} issues the documented federation-api
 * calls, driven by a recording {@link ExchangeFunction} stub (no live federation-
 * api). Asserts the request shapes match the federation-api controllers
 * field-for-field: /bundles/mine, PUT /bundles/{slug}, POST /moderation
 * (kind=instance-block, the recommend chain start).
 */
class FederationApiClientTest {

    static class Recorder implements ExchangeFunction {
        final List<ClientRequest> requests = new ArrayList<>();
        String bodyJson = "[]";

        @Override
        public Mono<ClientResponse> exchange(ClientRequest request) {
            requests.add(request);
            String path = request.url().getPath();
            if (path.endsWith("/body")) { // read-my-card-body -> raw source bytes
                return Mono.just(ClientResponse.create(HttpStatus.OK)
                        .header("Content-Type", "application/octet-stream")
                        .body("<h1>my card</h1>").build());
            }
            if (request.method() == HttpMethod.DELETE) { // delete -> 204 No Content
                return Mono.just(ClientResponse.create(HttpStatus.NO_CONTENT).build());
            }
            String body;
            if (path.endsWith("/bundles/mine") || path.contains("/bundles/slug/")) {
                body = "[{\"id\":1,\"ownerUserId\":\"alice\",\"slug\":\"my-card\","
                        + "\"contentHash\":\"abc\",\"visibility\":\"internal\"}]";
            } else if (path.endsWith("/moderation")) {
                body = "{\"id\":7,\"kind\":\"instance-block\",\"status\":\"recommended\",\"requester\":\"alice\"}";
            } else { // PUT bundle
                body = "{\"id\":2,\"ownerUserId\":\"alice\",\"slug\":\"my-card\",\"contentHash\":\"def\"}";
            }
            return Mono.just(ClientResponse.create(HttpStatus.OK)
                    .header("Content-Type", "application/json").body(body).build());
        }

        ClientRequest last() { return requests.get(requests.size() - 1); }
        boolean hit(String suffix) { return requests.stream().anyMatch(r -> r.url().getPath().endsWith(suffix)); }
    }

    private FederationApiClient clientFor(Recorder rec) {
        return new FederationApiClient(WebClient.builder().exchangeFunction(rec).build());
    }

    @Test
    void listMine_getsBundlesMine_boundToCard() {
        Recorder rec = new Recorder();
        List<UserModuleCard> cards = clientFor(rec).listMine().collectList().block();
        assertThat(rec.hit("/api/federation/bundles/mine")).isTrue();
        assertThat(rec.last().method()).isEqualTo(HttpMethod.GET);
        assertThat(cards).hasSize(1);
        assertThat(cards.get(0).slug()).isEqualTo("my-card");
        assertThat(cards.get(0).ownerUserId()).isEqualTo("alice");
    }

    @Test
    void put_putsBundleSlug_withParams() {
        Recorder rec = new Recorder();
        UserModuleCard saved = clientFor(rec)
                .put("my-card", "index.html", "internal", "{}", "<html/>".getBytes()).block();
        assertThat(rec.last().method()).isEqualTo(HttpMethod.PUT);
        assertThat(rec.last().url().getPath()).endsWith("/api/federation/bundles/my-card");
        assertThat(rec.last().url().getQuery()).contains("entryFile=index.html").contains("visibility=internal");
        assertThat(saved.contentHash()).isEqualTo("def");
    }

    @Test
    void readBody_getsBundleSlugBody_returnsRawSource() {
        Recorder rec = new Recorder();
        byte[] source = clientFor(rec).readBody("my-card").block();
        assertThat(rec.last().method()).isEqualTo(HttpMethod.GET);
        // hits the federation owner-scoped read-my-card-body endpoint EXACTLY.
        assertThat(rec.last().url().getPath()).endsWith("/api/federation/bundles/slug/my-card/body");
        assertThat(new String(source)).isEqualTo("<h1>my card</h1>");
    }

    @Test
    void delete_deletesBundleSlug() {
        Recorder rec = new Recorder();
        clientFor(rec).delete("my-card").block();
        assertThat(rec.last().method()).isEqualTo(HttpMethod.DELETE);
        // hits the federation owner-scoped delete endpoint EXACTLY (no /slug/ prefix,
        // matching DELETE /bundles/{slug}).
        assertThat(rec.last().url().getPath()).endsWith("/api/federation/bundles/my-card");
    }

    @Test
    void recommendInstanceBlock_postsModeration_withKindInstanceBlock() {
        Recorder rec = new Recorder();
        var resp = clientFor(rec).recommendInstanceBlock("evil.example", "spam").block();
        assertThat(rec.last().method()).isEqualTo(HttpMethod.POST);
        assertThat(rec.last().url().getPath()).endsWith("/api/federation/moderation");
        assertThat(resp).containsEntry("status", "recommended").containsEntry("kind", "instance-block");
    }
}
