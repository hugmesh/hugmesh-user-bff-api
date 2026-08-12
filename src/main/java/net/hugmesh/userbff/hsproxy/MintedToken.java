package net.hugmesh.userbff.hsproxy;

import java.time.Instant;

/**
 * The result of a homeserver-NATIVE token mint, IN-PROCESS ONLY. This is NEVER
 * serialised to any client — the proxy uses {@link #accessToken()} to inject the
 * {@code Authorization} header on the forwarded request and nothing more. The broker
 * also encrypts these into the custody row before returning.
 *
 * @param accessToken  the homeserver-native access token (plaintext, in-memory only)
 * @param refreshToken the refresh token when the platform issues one (Mastodon), else null
 * @param expiresAt    the access-token expiry when known (Mastodon), else null (Matrix)
 * @param localpart    the homeserver localpart the token authenticates
 */
public record MintedToken(String accessToken, String refreshToken, Instant expiresAt, String localpart) {
}
