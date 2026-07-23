package systems.hugmesh.userbff.federation;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import systems.hugmesh.commons.web.ApiException;

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
            } else if (path.contains("/moderation")) {
                body = "{\"id\":7,\"kind\":\"instance-block\",\"status\":\"recommended\",\"requester\":\"alice\"}";
            } else if (path.contains("/vanity/")) { // PUT publish
                body = "{\"slug\":\"profile-alice\",\"ownerUserId\":\"alice\",\"visibility\":\"public\","
                        + "\"enabled\":true}";
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
    void recommendInstanceBlock_postsToNarrowerRecommendPath_notTheModOnlySubmitSurface() {
        // Root-cause regression guard: this must hit the narrower, self-service
        // /recommend-instance-block sub-path — NOT the bare mod/admin-only
        // /api/federation/moderation submit surface — or a plain ROLE_MATRIX/
        // ROLE_MASTODON caller's forwarded bearer 403s downstream (the original bug).
        Recorder rec = new Recorder();
        var resp = clientFor(rec).recommendInstanceBlock("evil.example", "spam").block();
        assertThat(rec.last().method()).isEqualTo(HttpMethod.POST);
        assertThat(rec.last().url().getPath()).endsWith("/api/federation/moderation/recommend-instance-block");
        assertThat(resp).containsEntry("status", "recommended").containsEntry("kind", "instance-block");
    }

    // ---- vanity self-publish / self-unpublish ----

    @Test
    void publishVanity_putsVanityUsername_exactPath() {
        Recorder rec = new Recorder();
        var resp = clientFor(rec).publishVanity("alice", "Alice's Page").block();
        assertThat(rec.last().method()).isEqualTo(HttpMethod.PUT);
        assertThat(rec.last().url().getPath()).endsWith("/api/federation/vanity/alice");
        assertThat(resp).containsEntry("visibility", "public").containsEntry("enabled", true);
    }

    @Test
    void unpublishVanity_deletesVanityUsername_exactPath() {
        Recorder rec = new Recorder();
        clientFor(rec).unpublishVanity("alice").block();
        assertThat(rec.last().method()).isEqualTo(HttpMethod.DELETE);
        assertThat(rec.last().url().getPath()).endsWith("/api/federation/vanity/alice");
    }

    /** A recording {@link ExchangeFunction} that always returns a given error status
     *  with a body, so the client's error-mapping seam can be exercised. */
    private static ExchangeFunction erroring(HttpStatus status, String body) {
        return request -> Mono.just(ClientResponse.create(status)
                .header("Content-Type", "application/json")
                .body(body)
                .build());
    }

    /**
     * HONEST FAILURE: a 404 from federation-api (e.g. "no bundle uploaded yet for
     * profile-alice") must surface to the caller as an {@link ApiException} carrying
     * the SAME 404 status — never a generic 500, and never silently swallowed into a
     * fabricated success. This is the propagation contract {@link ProfileService}
     * relies on.
     */
    @Test
    void publishVanity_upstream404_mapsToApiException404_neverFakesSuccess() {
        FederationApiClient client = new FederationApiClient(WebClient.builder()
                .exchangeFunction(erroring(HttpStatus.NOT_FOUND,
                        "{\"error\":\"no uploaded bundle for profile-alice\"}"))
                .build());

        StepVerifier.create(client.publishVanity("alice", null))
                .expectErrorSatisfies(e -> {
                    assertThat(e).isInstanceOf(ApiException.class);
                    assertThat(((ApiException) e).status()).isEqualTo(HttpStatus.NOT_FOUND);
                    assertThat(e.getMessage()).contains("publish vanity profile");
                })
                .verify();
    }

    @Test
    void publishVanity_upstream403_mapsToApiException403() {
        FederationApiClient client = new FederationApiClient(WebClient.builder()
                .exchangeFunction(erroring(HttpStatus.FORBIDDEN, "{\"error\":\"not owner\"}"))
                .build());

        StepVerifier.create(client.publishVanity("alice", null))
                .expectErrorSatisfies(e -> {
                    assertThat(e).isInstanceOf(ApiException.class);
                    assertThat(((ApiException) e).status()).isEqualTo(HttpStatus.FORBIDDEN);
                })
                .verify();
    }

    @Test
    void unpublishVanity_upstreamError_mapsToApiException_neverFakesSuccess() {
        FederationApiClient client = new FederationApiClient(WebClient.builder()
                .exchangeFunction(erroring(HttpStatus.SERVICE_UNAVAILABLE, "down for maintenance"))
                .build());

        StepVerifier.create(client.unpublishVanity("alice"))
                .expectErrorSatisfies(e -> {
                    assertThat(e).isInstanceOf(ApiException.class);
                    assertThat(((ApiException) e).status()).isEqualTo(HttpStatus.SERVICE_UNAVAILABLE);
                    assertThat(e.getMessage()).contains("unpublish vanity profile");
                })
                .verify();
    }

    // ── CARDS honest status pass-through (the "404-or-500" e2e workaround killer) ──
    //
    // federation-api's owner-scoped 404 (a foreign/unknown slug) used to surface from
    // the BFF as an untranslated 500 (raw WebClientResponseException → the generic
    // handler); two user-ui feature files documented it as "one of 404 or 500". These
    // pin the fix: every cards leg maps the upstream status onto an ApiException with
    // the SAME code, so ApiExceptionHandler serves the semantically-correct response.

    @Test
    void readBody_upstream404_mapsToApiException404_notAGeneric500() {
        FederationApiClient client = new FederationApiClient(WebClient.builder()
                .exchangeFunction(erroring(HttpStatus.NOT_FOUND, "{\"error\":\"no such bundle\"}"))
                .build());

        StepVerifier.create(client.readBody("someone-elses-card"))
                .expectErrorSatisfies(e -> {
                    assertThat(e).isInstanceOf(ApiException.class);
                    assertThat(((ApiException) e).status()).isEqualTo(HttpStatus.NOT_FOUND);
                    assertThat(e.getMessage()).contains("read card body");
                })
                .verify();
    }

    @Test
    void delete_upstream404_mapsToApiException404_crossOwnerDenyStaysA404() {
        FederationApiClient client = new FederationApiClient(WebClient.builder()
                .exchangeFunction(erroring(HttpStatus.NOT_FOUND, "{\"error\":\"not your bundle\"}"))
                .build());

        StepVerifier.create(client.delete("someone-elses-card"))
                .expectErrorSatisfies(e -> {
                    assertThat(e).isInstanceOf(ApiException.class);
                    assertThat(((ApiException) e).status()).isEqualTo(HttpStatus.NOT_FOUND);
                    assertThat(e.getMessage()).contains("delete card");
                })
                .verify();
    }

    @Test
    void put_upstream400_mapsToApiException400_publishNeverFakesSuccess() {
        FederationApiClient client = new FederationApiClient(WebClient.builder()
                .exchangeFunction(erroring(HttpStatus.BAD_REQUEST, "{\"error\":\"bad manifest\"}"))
                .build());

        StepVerifier.create(client.put("my-card", "index.html", "internal", null, new byte[]{1}))
                .expectErrorSatisfies(e -> {
                    assertThat(e).isInstanceOf(ApiException.class);
                    assertThat(((ApiException) e).status()).isEqualTo(HttpStatus.BAD_REQUEST);
                    assertThat(e.getMessage()).contains("publish card");
                })
                .verify();
    }

    @Test
    void listMine_upstream503_mapsToApiException503() {
        FederationApiClient client = new FederationApiClient(WebClient.builder()
                .exchangeFunction(erroring(HttpStatus.SERVICE_UNAVAILABLE, "down"))
                .build());

        StepVerifier.create(client.listMine())
                .expectErrorSatisfies(e -> {
                    assertThat(e).isInstanceOf(ApiException.class);
                    assertThat(((ApiException) e).status()).isEqualTo(HttpStatus.SERVICE_UNAVAILABLE);
                    assertThat(e.getMessage()).contains("list cards");
                })
                .verify();
    }
}
