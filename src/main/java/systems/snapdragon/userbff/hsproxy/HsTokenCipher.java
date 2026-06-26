package systems.snapdragon.userbff.hsproxy;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

/**
 * AES-256-GCM authenticated encryption for the homeserver-NATIVE access/refresh tokens
 * AT REST. A user's Matrix/Mastodon token is long-lived secret material the BFF must hold
 * server-side (the proxy sidecars inject the homeserver-native token; the homeservers
 * reject the Casdoor JWT for the general API), so it is encrypted with a random 96-bit
 * nonce per record; the stored value is {@code base64(nonce || ciphertext || GCM-tag)}.
 *
 * <p>This MIRRORS admin-bff {@code MfaSecretCipher} EXACTLY (the just-merged MFA crypto
 * idiom) — same transform, nonce/tag/key sizes, base64 layout, key derivation, dark
 * posture and fail-closed decrypt — so the two BFFs hold long-lived secret material the
 * identical adversarially-verified way.
 *
 * <h3>Key source</h3>
 * The 256-bit data key is sourced from config ({@code app.hs-token.key}, fed by
 * ESO/Vault) — NEVER hardcoded, NEVER committed, NEVER logged. The configured value may
 * be either a base64/base64url 32-byte key (preferred — a real CSPRNG key) OR an
 * arbitrary passphrase, which is folded to 32 bytes via SHA-256.
 *
 * <h3>Dark posture</h3>
 * When no key is configured the cipher is INERT: {@link #isAvailable()} is false. Even
 * with {@code app.hs-token.enabled} now default true, a deployment that turns the proxy on
 * without provisioning a key gets a clean 503 rather than a plaintext-secret fallback. No
 * JDK fallback to plaintext EVER.
 */
@Component
public class HsTokenCipher {

    private static final Logger log = LoggerFactory.getLogger(HsTokenCipher.class);

    private static final String TRANSFORM = "AES/GCM/NoPadding";
    private static final int NONCE_BYTES = 12;   // 96-bit GCM nonce (NIST-recommended).
    private static final int TAG_BITS = 128;     // 128-bit GCM auth tag.
    private static final int KEY_BYTES = 32;     // AES-256.

    private final SecureRandom random = new SecureRandom();
    private final byte[] key; // null when unconfigured -> cipher inert.

    public HsTokenCipher(@Value("${app.hs-token.key:}") String configuredKey) {
        this.key = deriveKey(configuredKey);
        if (this.key == null) {
            // Dark-safe: no key -> custody mint refuses (never a plaintext fallback).
            // Logged WITHOUT any key material.
            log.info("[hs-token-cipher] no app.hs-token.key configured — custody token "
                    + "encryption is INERT until a key is provisioned (ships-dark posture)");
        }
    }

    /** Whether a usable encryption key is configured (the D6 mint requires this). */
    public boolean isAvailable() {
        return key != null;
    }

    /**
     * Encrypt {@code plaintext} (a homeserver-native access/refresh token) and return
     * {@code base64(nonce || ciphertext || tag)}. A fresh random 96-bit nonce per call.
     *
     * @throws IllegalStateException if no key is configured (caller must check
     *                               {@link #isAvailable()} first)
     */
    public String encrypt(String plaintext) {
        if (key == null) {
            throw new IllegalStateException("HS token key not configured");
        }
        try {
            byte[] nonce = new byte[NONCE_BYTES];
            random.nextBytes(nonce);
            Cipher cipher = Cipher.getInstance(TRANSFORM);
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(TAG_BITS, nonce));
            byte[] ct = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
            byte[] out = new byte[nonce.length + ct.length];
            System.arraycopy(nonce, 0, out, 0, nonce.length);
            System.arraycopy(ct, 0, out, nonce.length, ct.length);
            return Base64.getEncoder().encodeToString(out);
        } catch (Exception e) {
            // No key/algorithm fault should ever surface key material in the message.
            throw new IllegalStateException("HS token encryption failed", e);
        }
    }

    /**
     * Decrypt a {@code base64(nonce || ciphertext || tag)} blob back to the homeserver-
     * native token. Returns null on any error (tampered blob, wrong key, malformed
     * input, no key) — the proxy treats a null token as "cannot authenticate" and fails
     * closed (401 to caller).
     */
    public String decrypt(String stored) {
        if (key == null || stored == null || stored.isBlank()) {
            return null;
        }
        try {
            byte[] blob = Base64.getDecoder().decode(stored);
            if (blob.length <= NONCE_BYTES) {
                return null;
            }
            byte[] nonce = Arrays.copyOfRange(blob, 0, NONCE_BYTES);
            byte[] ct = Arrays.copyOfRange(blob, NONCE_BYTES, blob.length);
            Cipher cipher = Cipher.getInstance(TRANSFORM);
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(TAG_BITS, nonce));
            return new String(cipher.doFinal(ct), StandardCharsets.UTF_8);
        } catch (Exception e) {
            // GCM tag mismatch / malformed blob -> fail closed (never log the blob/key).
            log.debug("[hs-token-cipher] decrypt failed (fail-closed)");
            return null;
        }
    }

    /** Fold the configured key material to a 32-byte AES key, or null when unconfigured. */
    private static byte[] deriveKey(String configured) {
        if (configured == null || configured.isBlank()) {
            return null;
        }
        String v = configured.trim();
        // Prefer a base64/base64url 32-byte key (a real CSPRNG secret-store key).
        byte[] decoded = tryDecode(v);
        if (decoded != null && decoded.length == KEY_BYTES) {
            return decoded;
        }
        // Otherwise fold an arbitrary passphrase to 32 bytes via SHA-256.
        try {
            return MessageDigest.getInstance("SHA-256").digest(v.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 unavailable (JVM fault)", e);
        }
    }

    private static byte[] tryDecode(String v) {
        try {
            return Base64.getDecoder().decode(v);
        } catch (RuntimeException ignore) {
            try {
                return Base64.getUrlDecoder().decode(v);
            } catch (RuntimeException ignore2) {
                return null;
            }
        }
    }
}
