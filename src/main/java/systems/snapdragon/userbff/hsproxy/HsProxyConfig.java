package systems.snapdragon.userbff.hsproxy;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.netty.http.client.HttpClient;
import systems.snapdragon.userbff.federation.FederationHttpClientSsl;

/**
 * Wires the reactive {@link WebClient}s the D6 proxy controllers forward through to the
 * per-pod mTLS proxy sidecars ({@code tuwunel-proxy:4443} / {@code akkoma-proxy:4443}).
 * Both present this BFF's cluster-CA client identity (the existing
 * {@link FederationHttpClientSsl} keystore.p12) so the sidecars'
 * {@code ssl_verify_client on} handshake succeeds.
 *
 * <p>The clients carry NO read-timeout cap (streaming/long-poll passthrough —
 * {@code /_matrix/client/v3/sync} + {@code /api/v1/streaming/**} — must not be cut off;
 * the sidecar nginx already has a 300s read timeout + WS upgrade headers). Response
 * decompression is left to the sidecar; the BFF forwards bytes verbatim.
 *
 * <p>The feature is SHIPS-DARK behind {@code app.hs-token.enabled} (default false) — the
 * controllers 503 when disabled — so these beans are always present but inert until the
 * gate is flipped and a custody key + sidecars exist.
 */
@Configuration
public class HsProxyConfig {

    @Bean
    @Qualifier("matrixProxyWebClient")
    public WebClient matrixProxyWebClient(
            FederationHttpClientSsl mtls,
            @Value("${app.hs-token.matrix-url:https://tuwunel-proxy.snapdragon-backend.svc.cluster.local:4443}") String matrixUrl) {
        return proxyClient(mtls, matrixUrl);
    }

    @Bean
    @Qualifier("mastodonProxyWebClient")
    public WebClient mastodonProxyWebClient(
            FederationHttpClientSsl mtls,
            @Value("${app.hs-token.mastodon-url:https://akkoma-proxy.snapdragon-backend.svc.cluster.local:4443}") String mastodonUrl) {
        return proxyClient(mtls, mastodonUrl);
    }

    private static WebClient proxyClient(FederationHttpClientSsl mtls, String baseUrl) {
        HttpClient httpClient = mtls.customize(HttpClient.create());
        return WebClient.builder()
                .baseUrl(baseUrl)
                .clientConnector(new ReactorClientHttpConnector(httpClient))
                .build();
    }
}
