package systems.snapdragon.userbff.auth;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * A single-use PKCE (RFC 7636) pair the BFF generates SERVER-SIDE for the native-login
 * authorization request: a high-entropy {@code code_verifier} and its {@code S256}
 * {@code code_challenge} = BASE64URL(SHA-256(verifier)). Both are held ONLY on the server
 * for the duration of the (synchronous) login exchange and are NEVER sent to the browser.
 *
 * <p>Unlike the browser-PKCE {@code /bff/auth/callback} leg (where login-ui owns the
 * verifier in sessionStorage), the native-login leg does the whole authorize→code→token
 * round-trip inside this BFF, so the verifier proves the same party made both calls and
 * the challenge/verifier pair never leaves the process.
 */
public record Pkce(String verifier, String challenge) {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Base64.Encoder URL = Base64.getUrlEncoder().withoutPadding();

    /** Generate a fresh 32-byte-entropy verifier and its S256 challenge. */
    public static Pkce generate() {
        byte[] raw = new byte[32];
        RANDOM.nextBytes(raw);
        String verifier = URL.encodeToString(raw);
        return new Pkce(verifier, challengeFor(verifier));
    }

    /** A fresh random opaque state value (base64url, no padding). */
    public static String randomState() {
        byte[] raw = new byte[24];
        RANDOM.nextBytes(raw);
        return URL.encodeToString(raw);
    }

    private static String challengeFor(String verifier) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(verifier.getBytes(StandardCharsets.US_ASCII));
            return URL.encodeToString(digest);
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 unavailable (JVM fault)", e);
        }
    }
}
