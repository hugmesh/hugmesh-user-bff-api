package systems.hugmesh.userbff.media;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import systems.hugmesh.userbff.hsproxy.HsServiceTokenRow;
import systems.hugmesh.userbff.hsproxy.HsTokenCustody;
import systems.hugmesh.userbff.hsproxy.MintedToken;
import systems.hugmesh.userbff.hsproxy.ServiceTokenBroker;

import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * The homeserver media leg must inject the caller's per-user homeserver-NATIVE token on the
 * OUTBOUND upload — NOT the caller's Casdoor/custody JWT (the homeserver is a distinct trust
 * domain; forwarding the platform identity there is an info-disclosure the reverse-proxy
 * deliberately avoids). These capture the outbound Authorization header via a stub
 * ExchangeFunction and assert it is the native token, loaded from custody (minted on empty).
 */
class HomeserverMediaClientTest {

    private final AtomicReference<ClientRequest> captured = new AtomicReference<>();

    private WebClient capturingClient(String jsonResp) {
        ExchangeFunction ef = req -> {
            captured.set(req);
            return Mono.just(ClientResponse.create(HttpStatus.OK)
                    .header("Content-Type", MediaType.APPLICATION_JSON_VALUE)
                    .body(jsonResp).build());
        };
        return WebClient.builder().exchangeFunction(ef).build();
    }

    @Test
    void matrixUpload_injectsNativeCustodyToken_notCasdoorBearer() {
        HsTokenCustody custody = mock(HsTokenCustody.class);
        when(custody.loadAccessToken("casdoor:alice", HsServiceTokenRow.PLATFORM_MATRIX))
                .thenReturn(Mono.just("NATIVE-MATRIX-TOKEN"));
        ServiceTokenBroker broker = mock(ServiceTokenBroker.class);
        WebClient w = capturingClient("{\"content_uri\":\"mxc://x/y\"}");
        HomeserverMediaClient client = new HomeserverMediaClient(null, w, custody, broker);

        client.upload("casdoor:alice", "alice", "matrix", new byte[]{1, 2, 3}, "a.png", "image/png")
                .block();

        assertThat(captured.get().headers().getFirst("Authorization"))
                .isEqualTo("Bearer NATIVE-MATRIX-TOKEN");
        verifyNoInteractions(broker); // custody hit -> no mint
    }

    @Test
    void mastodonUpload_emptyCustody_mintsNativeToken_viaBroker() {
        HsTokenCustody custody = mock(HsTokenCustody.class);
        when(custody.loadAccessToken("casdoor:bob", HsServiceTokenRow.PLATFORM_MASTODON))
                .thenReturn(Mono.empty());
        ServiceTokenBroker broker = mock(ServiceTokenBroker.class);
        when(broker.mintMastodon("casdoor:bob", "bob"))
                .thenReturn(Mono.just(new MintedToken("MINTED-MASTODON", null, null, "bob")));
        WebClient w = capturingClient("{\"id\":\"media-9\"}");
        HomeserverMediaClient client = new HomeserverMediaClient(w, null, custody, broker);

        client.upload("casdoor:bob", "bob", "mastodon", new byte[]{9}, "b.png", "image/png")
                .block();

        assertThat(captured.get().headers().getFirst("Authorization"))
                .isEqualTo("Bearer MINTED-MASTODON");
    }

    @Test
    void fetchServed_alsoInjectsNativeToken() {
        HsTokenCustody custody = mock(HsTokenCustody.class);
        when(custody.loadAccessToken("casdoor:alice", HsServiceTokenRow.PLATFORM_MATRIX))
                .thenReturn(Mono.just("NATIVE-MATRIX-TOKEN"));
        ServiceTokenBroker broker = mock(ServiceTokenBroker.class);
        WebClient w = capturingClient("bytes-ignored");
        HomeserverMediaClient client = new HomeserverMediaClient(null, w, custody, broker);

        client.fetchServed("casdoor:alice", "alice", "matrix", "/_matrix/media/v3/download/x/y").block();

        assertThat(captured.get().headers().getFirst("Authorization"))
                .isEqualTo("Bearer NATIVE-MATRIX-TOKEN");
    }
}
