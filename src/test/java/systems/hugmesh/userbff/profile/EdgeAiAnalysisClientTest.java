package systems.hugmesh.userbff.profile;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for the avatar vision-moderation client. Drives the real Boot-4 codec via an
 * {@link ExchangeFunction} stub (the edge-ai-analysis {@code /v1/analyze/content/moderate}
 * contract), plus the dark (disabled) path and the FAIL-CLOSED error path.
 */
class EdgeAiAnalysisClientTest {

    private static EdgeAiAnalysisClient enabledReturning(HttpStatus status, String body) {
        ExchangeFunction stub = req -> Mono.just(ClientResponse.create(status)
                .header("Content-Type", MediaType.APPLICATION_JSON_VALUE)
                .body(body)
                .build());
        return new EdgeAiAnalysisClient(WebClient.builder().exchangeFunction(stub).build(), 5_000);
    }

    @Test
    void disabled_allowsWithoutCallingTheService() {
        EdgeAiAnalysisClient client = new EdgeAiAnalysisClient(null, 0);
        assertThat(client.isEnabled()).isFalse();
        StepVerifier.create(client.moderate(new byte[]{1, 2}))
                .assertNext(v -> {
                    assertThat(v.action()).isEqualTo("allow");
                    assertThat(v.blocks()).isFalse();
                })
                .verifyComplete();
    }

    @Test
    void enabled_safeImage_allows() {
        EdgeAiAnalysisClient client = enabledReturning(HttpStatus.OK,
                "{\"result\":{\"action\":\"allow\",\"classification\":\"safe\",\"confidence\":0.02,\"policy_hit\":false,\"perceptual_hash\":\"ff00\"}}");
        StepVerifier.create(client.moderate(new byte[]{1}))
                .assertNext(v -> {
                    assertThat(v.action()).isEqualTo("allow");
                    assertThat(v.blocks()).isFalse();
                    assertThat(v.perceptualHash()).isEqualTo("ff00");
                })
                .verifyComplete();
    }

    @Test
    void enabled_policyHit_rejects() {
        EdgeAiAnalysisClient client = enabledReturning(HttpStatus.OK,
                "{\"result\":{\"action\":\"reject\",\"classification\":\"nsfw\",\"confidence\":0.93,\"policy_hit\":true}}");
        StepVerifier.create(client.moderate(new byte[]{1}))
                .assertNext(v -> {
                    assertThat(v.action()).isEqualTo("reject");
                    assertThat(v.blocks()).isTrue();
                })
                .verifyComplete();
    }

    @Test
    void enabled_serviceError_failsClosed_reject() {
        EdgeAiAnalysisClient client = enabledReturning(HttpStatus.INTERNAL_SERVER_ERROR, "{}");
        StepVerifier.create(client.moderate(new byte[]{1}))
                .assertNext(v -> {
                    assertThat(v.action()).isEqualTo("reject"); // FAIL-CLOSED
                    assertThat(v.blocks()).isTrue();
                })
                .verifyComplete();
    }

    @Test
    void parseVerdict_missingAction_failsClosed() {
        assertThat(EdgeAiAnalysisClient.parseVerdict("{\"result\":{}}").action()).isEqualTo("reject");
        assertThat(EdgeAiAnalysisClient.parseVerdict("not json").action()).isEqualTo("reject");
    }
}
