package net.hugmesh.userbff.hsproxy;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.netty.http.client.HttpClient;
import net.hugmesh.userbff.federation.FederationHttpClientSsl;

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
 * <p>The feature is gated behind {@code app.hs-token.enabled} (now default true — the
 * proxy is the only homeserver path, the browser holds no token) — the controllers still
 * 503 unless a custody key + sidecars exist — so these beans are always present but inert
 * until both the gate is on and a custody key + sidecars are wired.
 */
@Configuration
public class HsProxyConfig {

    @Bean
    @Qualifier("matrixProxyWebClient")
    public WebClient matrixProxyWebClient(
            FederationHttpClientSsl mtls,
            @Value("${app.hs-token.matrix-url:https://tuwunel-proxy.hugmesh-backend.svc.cluster.local:4443}") String matrixUrl) {
        return proxyClient(mtls, matrixUrl);
    }

    @Bean
    @Qualifier("mastodonProxyWebClient")
    public WebClient mastodonProxyWebClient(
            FederationHttpClientSsl mtls,
            @Value("${app.hs-token.mastodon-url:https://akkoma-proxy.hugmesh-backend.svc.cluster.local:4443}") String mastodonUrl) {
        return proxyClient(mtls, mastodonUrl);
    }

    private static WebClient proxyClient(FederationHttpClientSsl mtls, String baseUrl) {
        HttpClient httpClient = mtls.customize(HttpClient.create());
        WebClient.Builder builder = WebClient.builder()
                .uriBuilderFactory(verbatimUriFactory(baseUrl))
                .clientConnector(new ReactorClientHttpConnector(httpClient));
        // Plain-HTTP homeserver base (compose: tuwunel:8008 / mastodon-web:3000, no TLS
        // sidecar): assert the edge protocol or mainline Mastodon's force_ssl 308s every
        // proxied API call. HsReverseProxy strips any INBOUND X-Forwarded-* so this
        // default is authoritative on the upstream leg. The cluster sidecar legs are
        // https — never added there (the sidecar owns proto metadata). tuwunel ignores
        // the header entirely, so sharing this builder path is harmless.
        if (baseUrl != null && baseUrl.startsWith("http://")) {
            builder.defaultHeader("X-Forwarded-Proto", "https");
        }
        return builder.build();
    }

    /**
     * URI factory for the proxy legs: {@link DefaultUriBuilderFactory.EncodingMode#NONE},
     * because the path {@link HsReverseProxy} forwards is the caller's RAW request path —
     * already percent-encoded exactly as the client sent it. The WebClient default
     * ({@code TEMPLATE_AND_VALUES}) treats {@code .uri(String)} as a URI <em>template</em>
     * and re-escapes {@code '%'}, so an encoded Matrix room id ({@code !r%3Alocalhost})
     * reached the homeserver as {@code !r%253Alocalhost} and every room-scoped CS-API
     * call failed (tuwunel decodes once: {@code %253A} → a literal {@code %3A} in the
     * room id). With NONE the raw path+query pass through verbatim; the request-line
     * grammar already forbids characters that would need encoding here, and
     * {@code HsReverseProxy#requireSafePath} rejects authority-shaped paths before any
     * URI is built. Package-visible so the proxy tests exercise the SAME factory.
     */
    static org.springframework.web.util.DefaultUriBuilderFactory verbatimUriFactory(String baseUrl) {
        var factory = new org.springframework.web.util.DefaultUriBuilderFactory(baseUrl);
        factory.setEncodingMode(org.springframework.web.util.DefaultUriBuilderFactory.EncodingMode.NONE);
        return factory;
    }
}
