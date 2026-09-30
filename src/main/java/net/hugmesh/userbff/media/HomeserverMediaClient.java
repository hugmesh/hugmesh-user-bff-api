package net.hugmesh.userbff.media;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import net.hugmesh.userbff.hsproxy.HsServiceTokenRow;
import net.hugmesh.userbff.hsproxy.HsTokenCustody;
import net.hugmesh.userbff.hsproxy.MintedToken;
import net.hugmesh.userbff.hsproxy.ServiceTokenBroker;

import java.util.Map;

/**
 * The REAL homeserver upload + served-byte re-fetch, via the EXISTING mTLS proxies
 * ({@code akkoma-proxy:4443} / {@code tuwunel-proxy:4443}, both {@code ssl_verify_client
 * on}) — NEVER by mounting the RWO media PVCs. The BFF presents its cluster-CA client
 * identity (reusing {@code FederationHttpClientSsl} via {@link MediaWebClientConfig}) and
 * forwards the CALLER's bearer only as far as the BFF, re-injecting it on the outbound
 * upload (reusing the {@code FederationWebClientConfig} bearer-forward filter).
 *
 * <p>This is the poison-BEFORE-ingest seam: the {@link MediaPoisonService} has already
 * cloaked the bytes; this client performs the actual homeserver upload of the POISONED
 * bytes and returns the resulting {@code media_id}/{@code mxc} EXACTLY as the homeserver
 * would (so the UI compose logic is untouched). It also re-fetches the served original +
 * thumbnails for the round-trip survival gate.
 *
 * <p>AUTHORIZATION — the OUTBOUND leg carries the caller's per-user homeserver-NATIVE
 * token (loaded from {@link HsTokenCustody}, minted on first use via
 * {@link ServiceTokenBroker}), NOT the caller's Casdoor/custody JWT. The homeserver is a
 * DISTINCT trust domain: forwarding the platform-wide Casdoor identity there (which the
 * shared {@code FederationWebClientConfig} bearer-forward filter used to do on this leg)
 * would let a homeserver log/replay it against every Casdoor-gated surface. This mirrors
 * the reverse-proxy invariant ({@code HsReverseProxy} strips the inbound Casdoor bearer
 * and injects the native token) — the media leg now does the same, using the SAME custody
 * identity the proxy uses so both talk to one homeserver account per user.
 *
 * <p>Per platform (base URLs grounded in the hugmesh-generator manifests, the proxy
 * Services, env-overridable):
 * <ul>
 *   <li>{@code mastodon} (akkoma) — POST {@code /api/v2/media} multipart; returns
 *       {@code {id, url, preview_url, ...}} (Mastodon MediaAttachment shape);</li>
 *   <li>{@code matrix} (tuwunel) — POST {@code /_matrix/media/v3/upload} octet-stream;
 *       returns {@code {content_uri: "mxc://..."}}.</li>
 * </ul>
 *
 * <p>STUB-SAFE: when wired with a {@code null} {@link WebClient} (no proxy URL / disabled)
 * every call errors fast via {@link #requireWired} so the service surfaces a clean 502
 * rather than a NPE — there is no silent success without a real homeserver write.
 */
public class HomeserverMediaClient {

    private static final Logger log = LoggerFactory.getLogger(HomeserverMediaClient.class);

    /** Akkoma (Mastodon-API) via akkoma-proxy:4443; null when not wired. */
    private final WebClient mastodon;
    /** tuwunel (Matrix) via tuwunel-proxy:4443; null when not wired. */
    private final WebClient matrix;
    /** Per-user homeserver-native token custody (same store the reverse-proxy uses). */
    private final HsTokenCustody custody;
    /** First-use mint of the native token (same broker the reverse-proxy uses). */
    private final ServiceTokenBroker broker;

    public HomeserverMediaClient(WebClient mastodon, WebClient matrix,
                                 HsTokenCustody custody, ServiceTokenBroker broker) {
        this.mastodon = mastodon;
        this.matrix = matrix;
        this.custody = custody;
        this.broker = broker;
    }

    private WebClient requireWired(String platform) {
        WebClient w = "matrix".equals(platform) ? matrix : mastodon;
        if (w == null) {
            throw new IllegalStateException("homeserver media proxy for '" + platform
                    + "' is not wired (app.media.proxy." + platform + ".enabled=false)");
        }
        return w;
    }

    /**
     * The per-user homeserver-native bearer to inject on the outbound leg: load the owner's
     * custody token for the platform, minting on first use (empty custody) exactly like the
     * reverse-proxy controllers, so the media leg talks to the SAME homeserver account the
     * proxy does. Fail-closed: an empty mint yields empty here and the caller errors rather
     * than uploading unauthenticated.
     */
    private Mono<String> nativeToken(String owner, String localpart, String platform) {
        boolean isMatrix = "matrix".equals(platform);
        String platformKey = isMatrix ? HsServiceTokenRow.PLATFORM_MATRIX : HsServiceTokenRow.PLATFORM_MASTODON;
        return custody.loadAccessToken(owner, platformKey)
                .switchIfEmpty(Mono.defer(() -> (isMatrix
                        ? broker.mintMatrix(owner, localpart)
                        : broker.mintMastodon(owner, localpart))
                        .map(MintedToken::accessToken)));
    }

    /**
     * Upload the (already-poisoned) bytes to the platform's homeserver via its mTLS
     * proxy and return the homeserver response as a raw Map — {@code id}/{@code url}/
     * {@code preview_url} for akkoma, {@code content_uri} for Matrix — so the controller
     * can return it to the UI EXACTLY as the homeserver would have. The caller bearer is
     * re-injected by the WebClient's bearer-forward filter.
     */
    public Mono<Map<String, Object>> upload(String owner, String localpart, String platform,
                                            byte[] bytes, String filename, String contentType) {
        WebClient w = requireWired(platform);
        return nativeToken(owner, localpart, platform).flatMap(token ->
                uploadWithToken(w, token, platform, bytes, filename, contentType));
    }

    /** The {@link #upload} leg once the native token is resolved: Matrix raw bytes, or
     *  Mastodon/akkoma multipart. */
    private Mono<Map<String, Object>> uploadWithToken(WebClient w, String token, String platform,
                                                      byte[] bytes, String filename, String contentType) {
        if ("matrix".equals(platform)) {
            // Matrix: raw bytes, content-type carried, filename as a query param.
            return w.post()
                    .uri(uri -> uri.path("/_matrix/media/v3/upload")
                            .queryParam("filename", filename == null ? "upload" : filename).build())
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                    .contentType(contentType == null ? MediaType.APPLICATION_OCTET_STREAM
                            : MediaType.parseMediaType(contentType))
                    .bodyValue(bytes)
                    .retrieve()
                    .bodyToMono(MAP_TYPE)
                    .doOnSuccess(r -> log.info("[homeserver] matrix upload ok -> {}",
                            r == null ? null : r.get("content_uri")));
        }
        // Mastodon/akkoma: multipart 'file'.
        org.springframework.http.client.MultipartBodyBuilder mb =
                new org.springframework.http.client.MultipartBodyBuilder();
        mb.part("file", new org.springframework.core.io.ByteArrayResource(bytes) {
            @Override public String getFilename() { return filename == null ? "upload" : filename; }
        }).contentType(contentType == null ? MediaType.APPLICATION_OCTET_STREAM
                : MediaType.parseMediaType(contentType));
        return w.post()
                .uri("/api/v2/media")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .contentType(MediaType.MULTIPART_FORM_DATA)
                .bodyValue(mb.build())
                .retrieve()
                .bodyToMono(MAP_TYPE)
                .doOnSuccess(r -> log.info("[homeserver] mastodon upload ok -> {}",
                        r == null ? null : r.get("id")));
    }

    /**
     * Re-fetch a served artifact (the post-ingest bytes the homeserver actually serves)
     * by its absolute served URL, via the same mTLS proxy — for the survival gate. The
     * URL comes from the homeserver's own upload response (e.g. akkoma {@code url}/
     * {@code preview_url}, or a Matrix download URL derived from the mxc), so it is a
     * relative path under the proxy base.
     */
    public Mono<byte[]> fetchServed(String owner, String localpart, String platform, String servedPath) {
        WebClient w = requireWired(platform);
        return nativeToken(owner, localpart, platform).flatMap(token -> w.get()
                .uri(servedPath)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .retrieve()
                .bodyToMono(byte[].class))
                .onErrorResume(e -> {
                    log.warn("[homeserver] re-fetch of served '{}' failed: {}", servedPath, e.toString());
                    return Mono.empty();
                });
    }

    @SuppressWarnings("unchecked")
    private static final Class<Map<String, Object>> MAP_TYPE =
            (Class<Map<String, Object>>) (Class<?>) Map.class;
}
