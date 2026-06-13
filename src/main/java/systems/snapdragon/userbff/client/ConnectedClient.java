package systems.snapdragon.userbff.client;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.time.Instant;

/**
 * One CONNECTED APP or DEVICE belonging to the caller — a native OAuth app
 * (Element / Tusky / Ivory) or a login device session the user has registered against
 * a homeserver (akkoma = mastodon, Matrix = matrix) through the gateway passthrough.
 *
 * <p>This is BOTH the wire shape returned to the user-ui Connected-Apps-and-Devices
 * view AND the persisted {@code connected_client_audit} row. {@code owner} is the
 * Casdoor JWT subject and is NEVER accepted from the request body — the controller
 * always sets it from the token, so a user can only ever see/revoke their OWN clients.
 *
 * @param id          app-generated UUID (the audit-row PK; the {@code DELETE /{id}}
 *                    path variable).
 * @param owner       Casdoor JWT subject (the user).
 * @param platform    {@code matrix} or {@code mastodon}.
 * @param clientKind  {@code oauth-app} (an OAuth application grant) or {@code device}
 *                    (a login device session).
 * @param externalRef the homeserver-side id (appId / deviceId) a revoke targets + the
 *                    per-credential gateway revocation key is keyed by.
 * @param label       human-friendly name (client app / device display name).
 * @param createdAt   when this audit row was first recorded.
 * @param revokedAt   when the user revoked the credential ({@code null} = active).
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record ConnectedClient(
        String id,
        String owner,
        String platform,
        String clientKind,
        String externalRef,
        String label,
        Instant createdAt,
        Instant revokedAt) {

    public static final String KIND_OAUTH_APP = "oauth-app";
    public static final String KIND_DEVICE = "device";

    public static boolean validPlatform(String p) {
        return "matrix".equals(p) || "mastodon".equals(p);
    }

    public static boolean validKind(String k) {
        return KIND_OAUTH_APP.equals(k) || KIND_DEVICE.equals(k);
    }

    public boolean active() {
        return revokedAt == null;
    }
}
