package systems.hugmesh.userbff.hsproxy;

import org.junit.jupiter.api.Test;

import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * AES-256-GCM at-rest cipher for the homeserver-native custody tokens: round-trip,
 * per-record random nonce, tamper-detection (a flipped byte fails the GCM tag → null),
 * wrong-key fails closed, and the dark-safe INERT posture when no key is configured.
 * Mirrors admin-bff {@code MfaSecretCipherTest}.
 */
class HsTokenCipherTest {

    private final HsTokenCipher cipher = new HsTokenCipher(
            Base64.getEncoder().encodeToString(new byte[32])); // 32-byte test key

    @Test
    void roundTrips() {
        String token = "syt_native_matrix_token_abc123";
        String enc = cipher.encrypt(token);
        assertThat(enc).isNotEqualTo(token);
        assertThat(cipher.decrypt(enc)).isEqualTo(token);
    }

    @Test
    void usesFreshNoncePerRecord() {
        String token = "syt_native_matrix_token_abc123";
        assertThat(cipher.encrypt(token)).isNotEqualTo(cipher.encrypt(token));
    }

    @Test
    void tamperedBlobFailsClosed() {
        String enc = cipher.encrypt("syt_native_matrix_token_abc123");
        byte[] raw = Base64.getDecoder().decode(enc);
        raw[raw.length - 1] ^= 0x01; // flip a tag byte
        assertThat(cipher.decrypt(Base64.getEncoder().encodeToString(raw))).isNull();
        assertThat(cipher.decrypt("not-base64!!!")).isNull();
        assertThat(cipher.decrypt(null)).isNull();
    }

    @Test
    void wrongKeyCannotDecrypt() {
        String enc = cipher.encrypt("syt_native_matrix_token_abc123");
        byte[] otherKey = new byte[32];
        otherKey[0] = 1;
        HsTokenCipher other = new HsTokenCipher(Base64.getEncoder().encodeToString(otherKey));
        assertThat(other.decrypt(enc)).isNull();
    }

    @Test
    void unconfiguredCipherIsInert() {
        HsTokenCipher inert = new HsTokenCipher("");
        assertThat(inert.isAvailable()).isFalse();
        assertThat(inert.decrypt("anything")).isNull();
    }

    @Test
    void passphraseIsFoldedToAKey() {
        HsTokenCipher pass = new HsTokenCipher("a-human-passphrase-not-32-bytes");
        assertThat(pass.isAvailable()).isTrue();
        String enc = pass.encrypt("native-token");
        assertThat(pass.decrypt(enc)).isEqualTo("native-token");
    }
}
