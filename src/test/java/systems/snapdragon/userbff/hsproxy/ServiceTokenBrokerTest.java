package systems.snapdragon.userbff.hsproxy;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Guards the Boot-4 JSON decode path of the homeserver token broker.
 *
 * <p>Before the Boot-4 fix the broker decoded responses with
 * {@code bodyToMono(com.fasterxml.jackson.databind.JsonNode.class)} — a Jackson-2
 * type the Boot-4 reactive WebFlux codec (Jackson 3 / tools.jackson) cannot
 * decode, throwing a {@code CodecException} so EVERY Matrix/Mastodon token mint
 * failed at runtime. It was silent because no test exercised the broker's real
 * HTTP decode.
 *
 * <p>These tests stub the homeserver exchange and drive the public
 * {@code mintMatrix}/{@code mintMastodon} flows end-to-end through the real codec,
 * so a regression to a codec-incompatible decode fails fast here.
 */
class ServiceTokenBrokerTest {

    /** An exchange that answers every request with the given JSON body (200). */
    private static ExchangeFunction jsonStub(String body) {
        return request -> Mono.just(ClientResponse.create(HttpStatus.OK)
                .header("Content-Type", MediaType.APPLICATION_JSON_VALUE)
                .body(body)
                .build());
    }

    private static ServiceTokenBroker brokerFor(String responseBody) {
        WebClient hs = WebClient.builder()
                .exchangeFunction(jsonStub(responseBody))
                .build();
        HsTokenCustody custody = mock(HsTokenCustody.class);
        when(custody.upsert(any(), any(), any(), any(), any(), any()))
                .thenReturn(Mono.empty());
        HsTokenRevocationHashWriter hashWriter =
                mock(HsTokenRevocationHashWriter.class);
        when(hashWriter.recordBrokered(any(), any(), any()))
                .thenReturn(Mono.empty());
        return new ServiceTokenBroker(hs, hs, "svc-pw", custody, hashWriter);
    }

    /** Broker with the given service password (and a stub HS that would 200 if reached). */
    private static ServiceTokenBroker brokerWithPassword(String svcPassword) {
        WebClient hs = WebClient.builder()
                .exchangeFunction(jsonStub("{\"access_token\":\"should-not-be-reached\"}"))
                .build();
        return new ServiceTokenBroker(hs, hs, svcPassword,
                mock(HsTokenCustody.class), mock(HsTokenRevocationHashWriter.class));
    }

    @Test
    void mintMatrix_decodesSynapseJson_throughTheBoot4Jackson3Codec() {
        // Synapse /register returns an access_token directly (one-shot success).
        ServiceTokenBroker broker = brokerFor(
                "{\"access_token\":\"syt_abc\",\"user_id\":\"@bob:hs\"}");

        StepVerifier.create(broker.mintMatrix("sub-1", "bob"))
                .assertNext(token ->
                        assertThat(token.accessToken()).isEqualTo("syt_abc"))
                .verifyComplete();
    }

    @Test
    void mintMastodon_decodesOauthJson_throughTheBoot4Jackson3Codec() {
        ServiceTokenBroker broker = brokerFor(
                "{\"access_token\":\"mst_xyz\",\"token_type\":\"Bearer\"}");

        StepVerifier.create(broker.mintMastodon("sub-1", "bob"))
                .assertNext(token ->
                        assertThat(token.accessToken()).isEqualTo("mst_xyz"))
                .verifyComplete();
    }

    // --- Fail-closed when the service password is unprovisioned (empty default) ---------
    // app.hs-token.svc-password now carries an EMPTY default so an unset secret boots the
    // context cleanly instead of crashing on an unresolved placeholder; a mint must then
    // 503 BEFORE touching the homeserver (mirrors an unconfigured custody key → 503).

    @Test
    void mintMatrix_failsClosed503_whenServicePasswordUnset() {
        ServiceTokenBroker broker = brokerWithPassword("");

        StepVerifier.create(broker.mintMatrix("sub-1", "bob"))
                .expectErrorSatisfies(e -> assertThat(e)
                        .isInstanceOf(ResponseStatusException.class)
                        .extracting(ex -> ((ResponseStatusException) ex).getStatusCode().value())
                        .isEqualTo(503))
                .verify();
    }

    @Test
    void mintMastodon_failsClosed503_whenServicePasswordBlank() {
        ServiceTokenBroker broker = brokerWithPassword("   ");

        StepVerifier.create(broker.mintMastodon("sub-1", "bob"))
                .expectErrorSatisfies(e -> assertThat(e)
                        .isInstanceOf(ResponseStatusException.class)
                        .extracting(ex -> ((ResponseStatusException) ex).getStatusCode().value())
                        .isEqualTo(503))
                .verify();
    }
}
