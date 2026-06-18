package systems.snapdragon.userbff.hsproxy;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.data.r2dbc.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import systems.snapdragon.userbff.support.TestDatabaseConfig;

import java.time.Instant;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * R2DBC slice test for the D6 custody store against H2 (PostgreSQL-compat) with the REAL
 * Liquibase changelog applied (013 {@code hs_service_token}). Drives {@link HsTokenCustody}
 * over the real {@link HsServiceTokenR2dbcRepository} + a real {@link HsTokenCipher}.
 *
 * <p>Asserts:
 * <ul>
 *   <li>encrypt + upsert + decrypt round-trip (the stored column is NEVER the plaintext);</li>
 *   <li>the custody UPSERT is a true upsert: a re-mint UPDATEs in place (one row per
 *       owner+platform), and the localpart/expiry/refresh rotate;</li>
 *   <li><b>the cross-user isolation keystone</b>: subject A can never read, re-use,
 *       refresh, or delete subject B's custody token — every predicate is owner-scoped.</li>
 * </ul>
 */
@DataR2dbcTest
@Import(TestDatabaseConfig.class)
class HsTokenCustodyRepositoryTest {

    @Autowired HsServiceTokenR2dbcRepository repo;

    private final HsTokenCipher cipher = new HsTokenCipher(
            Base64.getEncoder().encodeToString(new byte[32]));

    private HsTokenCustody custody() {
        return new HsTokenCustody(repo, cipher);
    }

    @Test
    void encryptUpsertDecrypt_roundTrip_andStoredColumnIsCiphertext() {
        HsTokenCustody c = custody();
        c.upsert("alice", HsServiceTokenRow.PLATFORM_MATRIX, "native-alice-tok", null, null, "alice")
                .block();

        // The decrypted-load surface gives the plaintext back...
        assertThat(c.loadAccessToken("alice", HsServiceTokenRow.PLATFORM_MATRIX).block())
                .isEqualTo("native-alice-tok");
        // ...but the stored column is the AES-GCM ciphertext, never the plaintext.
        HsServiceTokenRow row = repo.findByOwnerSubjectAndPlatform("alice",
                HsServiceTokenRow.PLATFORM_MATRIX).block();
        assertThat(row).isNotNull();
        assertThat(row.accessTokenEnc()).isNotNull().isNotEqualTo("native-alice-tok");
        assertThat(row.ownerSubject()).isEqualTo("alice");
    }

    @Test
    void upsert_isTrueUpsert_oneRowPerOwnerPlatform_andRotates() {
        HsTokenCustody c = custody();
        // Unique owner+platform so this assertion is independent of rows other test
        // methods left in the shared H2 mem context.
        c.upsert("rotator", HsServiceTokenRow.PLATFORM_MASTODON, "tok-v1", "refresh-v1",
                Instant.now().plusSeconds(3600), "rotator").block();
        c.upsert("rotator", HsServiceTokenRow.PLATFORM_MASTODON, "tok-v2", "refresh-v2",
                Instant.now().plusSeconds(7200), "rotator").block();

        // Exactly one row for (rotator, mastodon) — the second mint UPDATEd in place.
        assertThat(repo.findAll()
                .filter(r -> "rotator".equals(r.ownerSubject())
                        && HsServiceTokenRow.PLATFORM_MASTODON.equals(r.platform()))
                .count().block()).isEqualTo(1L);
        assertThat(c.loadAccessToken("rotator", HsServiceTokenRow.PLATFORM_MASTODON).block())
                .isEqualTo("tok-v2");
    }

    @Test
    void crossUserIsolation_AcannotReadReuseRefreshOrDeleteBsToken() {
        HsTokenCustody c = custody();
        c.upsert("alice", HsServiceTokenRow.PLATFORM_MATRIX, "alice-secret", null, null, "alice").block();
        c.upsert("bob", HsServiceTokenRow.PLATFORM_MATRIX, "bob-secret", null, null, "bob").block();

        // A's load only ever yields A's token — bob's is structurally unreachable.
        assertThat(c.loadAccessToken("alice", HsServiceTokenRow.PLATFORM_MATRIX).block())
                .isEqualTo("alice-secret");
        // There is no way to fetch bob's token via alice's owner key.
        assertThat(repo.findByOwnerSubjectAndPlatform("alice", HsServiceTokenRow.PLATFORM_MATRIX)
                .block().accessTokenEnc())
                .isNotEqualTo(repo.findByOwnerSubjectAndPlatform("bob", HsServiceTokenRow.PLATFORM_MATRIX)
                        .block().accessTokenEnc());

        // A's "re-mint" (upsert keyed on A) can NEVER overwrite bob's row.
        c.upsert("alice", HsServiceTokenRow.PLATFORM_MATRIX, "alice-rotated", null, null, "alice").block();
        assertThat(c.loadAccessToken("bob", HsServiceTokenRow.PLATFORM_MATRIX).block())
                .isEqualTo("bob-secret");

        // A's delete (owner-scoped) does NOT touch bob's row.
        assertThat(c.delete("alice", HsServiceTokenRow.PLATFORM_MATRIX).block()).isEqualTo(1L);
        assertThat(c.loadAccessToken("alice", HsServiceTokenRow.PLATFORM_MATRIX).blockOptional()).isEmpty();
        assertThat(c.loadAccessToken("bob", HsServiceTokenRow.PLATFORM_MATRIX).block())
                .isEqualTo("bob-secret");
        // bob's delete keyed on bob's missing 'mastodon' platform is a no-op (0 rows).
        assertThat(c.delete("bob", HsServiceTokenRow.PLATFORM_MASTODON).block()).isEqualTo(0L);
    }

    @Test
    void load_withInertCipher_failsClosed_noPlaintextLeak() {
        // Persist a row with a real cipher, then read it back through an INERT cipher.
        custody().upsert("carol", HsServiceTokenRow.PLATFORM_MATRIX, "carol-tok", null, null, "carol")
                .block();
        HsTokenCustody inert = new HsTokenCustody(repo, new HsTokenCipher(""));
        assertThat(inert.cipherAvailable()).isFalse();
        // The row exists but cannot be decrypted → empty (fail-closed), never plaintext.
        assertThat(inert.loadAccessToken("carol", HsServiceTokenRow.PLATFORM_MATRIX).blockOptional())
                .isEmpty();
    }
}
