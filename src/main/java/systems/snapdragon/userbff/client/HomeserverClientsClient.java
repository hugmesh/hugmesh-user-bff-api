package systems.snapdragon.userbff.client;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * CONNECTED APPS & DEVICES homeserver seam — one implementation per platform
 * (akkoma = mastodon, Matrix = matrix). LISTS the user's native OAuth apps + device
 * sessions and REVOKES one, via the homeserver client API reached THROUGH the mTLS
 * proxy (the same outbound client-cert presentation {@code FederationHttpClientSsl}
 * configures), forwarding the caller's homeserver bearer.
 *
 * <p>GATED STUB-SEAM (scope-guard), mirroring {@link
 * systems.snapdragon.userbff.silence.HomeserverHideClient} / {@code ExternalBlockClient}:
 * defaults OFF ({@code external.<platform>.enabled=false}); when disabled
 * {@link #list(String, String)} returns an EMPTY stream and {@link #revoke(String,
 * String, String)} returns {@code false} (no live call) — NEVER a hard-fail. The
 * homeserver remains the live source of truth; this seam is the read/revoke transport,
 * and the durable {@code connected_client_audit} row is the BFF-owned audit record.
 *
 * <p>Both calls are GATED SEAMS, never hard-fail (the homeserver/gateway call is a
 * best-effort leg): the service catches errors and continues from the audit row, so a
 * not-yet-deployed homeserver leg never breaks list/revoke.
 */
public interface HomeserverClientsClient {

    /** {@code "matrix"} or {@code "mastodon"} — the platform this seam talks to. */
    String platform();

    /**
     * List the user's connected apps + device sessions on this platform. {@code bearer}
     * is the caller's homeserver token (forwarded). Returns an empty stream when the
     * seam is disabled / stubbed (the durable audit rows still surface in the service).
     */
    Flux<ConnectedClient> list(String localpart, String bearer);

    /**
     * Revoke one app/device on this platform by its homeserver-side id
     * ({@code externalRef} = appId/deviceId). Returns whether a LIVE call was made
     * ({@code false} = documented stub / disabled). Best-effort: a stub/failure never
     * hard-fails the revoke (the per-credential gateway revocation key + the audit
     * stamp are the durable enforcement).
     */
    Mono<Boolean> revoke(String localpart, String externalRef, String bearer);
}
