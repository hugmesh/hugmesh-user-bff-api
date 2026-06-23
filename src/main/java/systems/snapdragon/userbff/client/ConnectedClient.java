package systems.snapdragon.userbff.client;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import systems.snapdragon.userbff.web.PlatformKind;

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

    /** The {@code oauth-app} client-kind token — retained constant, now sourced from the
     *  {@link ClientKind#OAUTH_APP} enum value so the literal lives in ONE place. */
    public static final String KIND_OAUTH_APP = ClientKind.OAUTH_APP.value();
    /** The {@code device} client-kind token — retained constant, sourced from
     *  {@link ClientKind#DEVICE}. */
    public static final String KIND_DEVICE = ClientKind.DEVICE.value();

    /** Accept iff {@code p} is a valid external platform token — delegates to the shared
     *  {@link PlatformKind} lens so there is ONE source of truth (behaviour identical). */
    public static boolean validPlatform(String p) {
        return PlatformKind.isValid(p);
    }

    /** Accept iff {@code k} is a valid client-kind token — the closed {@code oauth-app|device}
     *  set is now modelled by {@link ClientKind}; this guard delegates to it. */
    public static boolean validKind(String k) {
        return ClientKind.isValid(k);
    }

    public boolean active() {
        return revokedAt == null;
    }
}
