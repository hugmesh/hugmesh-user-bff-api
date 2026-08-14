package net.hugmesh.userbff.profile;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import net.hugmesh.userbff.support.TestDatabaseConfig;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * R2DBC slice test for {@link UserProfileRepository#updateAvatarUrl} against H2
 * (PostgreSQL-compat) with the REAL Liquibase changelog (incl. 014 avatar_url)
 * applied by {@link TestDatabaseConfig}. Verifies BOTH legs of the avatar-only
 * upsert:
 * <ul>
 *   <li>UPDATE leg — an EXISTING profile gets its avatar_url set without disturbing
 *       its other columns;</li>
 *   <li>INSERT-if-absent leg — an avatar set BEFORE any profile exists creates a
 *       minimal owner row carrying the avatar;</li>
 *   <li>a later profile {@code save()} does NOT clear the avatar (the main upsert
 *       omits avatar_url);</li>
 *   <li>owner isolation — the avatar lands only on the owner's row.</li>
 * </ul>
 */
@DataR2dbcTest
@Import({TestDatabaseConfig.class, UserProfileRepository.class})
class UserProfileRepositoryAvatarTest {

    @Autowired UserProfileRepository repo;
    // @DataR2dbcTest auto-configures the R2DBC repositories, so the raw store is injectable.
    @Autowired UserProfileR2dbcRepository raw;

    // This slice shares one H2 DB; seed rows would otherwise leak across methods AND into
    // sibling repo slice tests (e.g. UserProfileRepositoryTest.upsert_roundTrip). Wipe the
    // table before each method and after the class's last method to keep the DB pristine.
    @BeforeEach void clean() { raw.deleteAll().block(); }
    @AfterEach  void wipe()  { raw.deleteAll().block(); }

    @Test
    void updateAvatarUrl_onExistingProfile_setsAvatar_keepsOtherColumns() {
        repo.save(new UserProfile("alice", "f", "she/her", "UTC", "Alice", "public", true)).block();

        Long matched = repo.updateAvatarUrl("alice", "mxc://home/pic1", "default", PNG, "image/png").block();
        assertThat(matched).isEqualTo(1L);

        UserProfile got = repo.find("alice").block();
        assertThat(got.avatarUrl()).isEqualTo("mxc://home/pic1");
        // other columns untouched
        assertThat(got.displayName()).isEqualTo("Alice");
        assertThat(got.pronouns()).isEqualTo("she/her");
        assertThat(got.visibility()).isEqualTo("public");
    }

    @Test
    void updateAvatarUrl_beforeAnyProfile_insertsMinimalRowWithAvatar() {
        assertThat(repo.find("bob").blockOptional()).isEmpty();

        Long matched = repo.updateAvatarUrl("bob", "mxc://home/pic2", "default", PNG, "image/png").block();
        assertThat(matched).isEqualTo(1L);

        UserProfile got = repo.find("bob").block();
        assertThat(got).isNotNull();
        assertThat(got.userId()).isEqualTo("bob");
        assertThat(got.avatarUrl()).isEqualTo("mxc://home/pic2");
        // minimal row: default visibility, vanity off, no vanity username
        assertThat(got.visibility()).isEqualTo(UserProfile.DEFAULT_VISIBILITY);
        assertThat(got.vanitySubdomainEnabled()).isFalse();
        assertThat(got.vanityUsername()).isNull();
    }

    @Test
    void profileSave_doesNotClearAvatar() {
        repo.save(new UserProfile("carol", null, null, null, "Carol", "internal", false)).block();
        repo.updateAvatarUrl("carol", "mxc://home/pic3", "default", PNG, "image/png").block();

        // a subsequent profile edit must NOT wipe the avatar (main upsert omits it)
        repo.save(new UserProfile("carol", null, null, null, "Carol Edited", "internal", false)).block();

        UserProfile got = repo.find("carol").block();
        assertThat(got.displayName()).isEqualTo("Carol Edited");
        assertThat(got.avatarUrl()).isEqualTo("mxc://home/pic3");
    }

    /** 8-byte PNG signature — enough to prove BYTEA round-trips on the H2 slice. */
    private static final byte[] PNG =
            new byte[] {(byte) 0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a};

    @Test
    void updateAvatarUrl_storesTheBytes_andFindAvatarBodyReturnsThem() {
        // 022: the pixels are persisted WITH the ref. Before that column the bytes
        // were discarded after the (stub-gated) homeserver upload, so the row held a
        // ref to no image and every avatar rendered broken.
        repo.save(new UserProfile("dave", null, null, null, "Dave", "internal", false)).block();
        repo.updateAvatarUrl("dave", "mxc://home/pic4", "default", PNG, "image/png").block();

        var body = repo.findAvatarBody("dave", "default").block();
        assertThat(body).isNotNull();
        assertThat(body.bytes()).isEqualTo(PNG);
        assertThat(body.contentType()).isEqualTo("image/png");
    }

    @Test
    void findAvatarBody_isEmptyForSomeoneWhoNeverUploaded() {
        repo.save(new UserProfile("erin", null, null, null, "Erin", "internal", false)).block();
        assertThat(repo.findAvatarBody("erin", "default").blockOptional()).isEmpty();
    }

    @Test
    void updateAvatarUrl_ownerIsolation() {
        repo.save(new UserProfile("alice", null, null, null, "Alice", "internal", false)).block();
        repo.save(new UserProfile("bob", null, null, null, "Bob", "internal", false)).block();

        repo.updateAvatarUrl("alice", "mxc://home/alicepic", "default", PNG, "image/png").block();

        assertThat(repo.find("alice").block().avatarUrl()).isEqualTo("mxc://home/alicepic");
        // bob's avatar is untouched (still null)
        assertThat(repo.find("bob").block().avatarUrl()).isNull();
    }
}
