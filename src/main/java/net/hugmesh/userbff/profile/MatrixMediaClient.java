package net.hugmesh.userbff.profile;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.UUID;

/**
 * Uploads a user's PROFILE-PICTURE bytes to the in-cluster Matrix homeserver
 * (tuwunel) media repository and returns the resulting {@code mxc://} URL. Base URL
 * is grounded in the hugmesh-generator manifests
 * {@code http://tuwunel.hugmesh-backend.svc.cluster.local:8008} (env-overridable
 * via {@code MATRIX_URL}).
 *
 * <p>Documented Matrix client-server media upload:
 * {@code POST /_matrix/media/v1/upload?filename=<name>} with the raw image bytes +
 * the image {@code Content-Type}, returning {@code {"content_uri":"mxc://..."}}.
 *
 * <p>STUB STATUS (mirrors {@code MatrixBlockClient}): the per-user Matrix access-token
 * acquisition (the BFF would need the caller's Matrix token, brokered via the
 * admin-bff ServiceTokenBroker) is out of scope here, so the live POST is GATED OFF
 * by default (enabled only when a {@link WebClient} is wired via
 * {@code avatar.matrix.enabled=true}). When DISABLED this returns a DETERMINISTIC
 * stub {@code mxc://stub.invalid/<id>} so avatar storage works end-to-end + ships
 * dark + is unit-testable — it NEVER errors, so the durable {@code avatar_url} row
 * always stands. Validate token brokering before flipping the flag.
 *
 * <p>The image bytes are NEVER logged.
 */
public class MatrixMediaClient {

    private static final Logger log = LoggerFactory.getLogger(MatrixMediaClient.class);

    /** The documented homeserver media-upload path (filename is a fixed label). */
    private static final String UPLOAD_PATH = "/_matrix/media/v1/upload?filename=avatar";

    /** Stub mxc:// authority used when the live upload is disabled. */
    private static final String STUB_AUTHORITY = "stub.invalid";

    /** Null unless avatar.matrix.enabled=true — when null every upload is a documented stub. */
    private final WebClient http;

    public MatrixMediaClient(WebClient http) {
        this.http = http;
    }

    /**
     * Upload the profile-picture bytes and return the {@code mxc://} URL.
     *
     * @param localpart the owner (JWT subject) — used ONLY to derive a deterministic
     *                  stub id; never sent as the bytes / never logged with the bytes.
     * @param bytes     the raw image bytes (never logged).
     * @param contentType the image MIME type (e.g. {@code image/png}).
     * @return the {@code mxc://} URL (a stub when disabled, the homeserver's
     *         {@code content_uri} when enabled).
     */
    public Mono<String> upload(String localpart, byte[] bytes, String contentType) {
        if (http == null) {
            return Mono.just(stubMxc(localpart));
        }
        return uploadLive(bytes, contentType);
    }

    /** A deterministic stub mxc:// for the owner (stable per owner so reads are
     *  predictable in the dark-shipped mode + in tests). */
    private static String stubMxc(String localpart) {
        String id = UUID.nameUUIDFromBytes(
                ("avatar:" + (localpart == null ? "" : localpart)).getBytes()).toString();
        log.info("[matrix-media] (stub) profile avatar stored as mxc://{}/{} — live homeserver "
                + "upload disabled (avatar.matrix.enabled=false)", STUB_AUTHORITY, id);
        return "mxc://" + STUB_AUTHORITY + "/" + id;
    }

    /** POST the bytes to the homeserver media repo and read {@code content_uri}. */
    private Mono<String> uploadLive(byte[] bytes, String contentType) {
        MediaType type = contentType == null ? MediaType.APPLICATION_OCTET_STREAM
                : MediaType.parseMediaType(contentType);
        return http.post()
                .uri(UPLOAD_PATH)
                .contentType(type)
                .bodyValue(bytes)
                .retrieve()
                .bodyToMono(UploadResponse.class)
                .map(UploadResponse::contentUri)
                .doOnSuccess(uri -> log.info("[matrix-media] profile avatar uploaded -> {}", uri));
    }

    /** The homeserver media-upload response: {@code {"content_uri":"mxc://..."}}.
     *  The component name matches the JSON field so Jackson binds it without an
     *  explicit {@code @JsonProperty}; {@link #contentUri()} is the readable accessor. */
    record UploadResponse(String content_uri) {
        /** The {@code content_uri} field (the mxc:// URL of the stored media). */
        String contentUri() {
            return content_uri;
        }
    }
}
