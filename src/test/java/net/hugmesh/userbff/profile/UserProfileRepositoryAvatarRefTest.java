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
 * R2DBC slice test for the 023 AVATAR SERVE HANDLE
 * ({@link UserProfileRepository#ensureAvatarRef} /
 * {@link UserProfileRepository#findAvatarBodyByRef}) against H2 (PostgreSQL-compat)
 * with the REAL Liquibase changelog applied by {@link TestDatabaseConfig}.
 *
 * <p>The handle is what lets a forum VN profile name WHOSE avatar to draw without
 * putting a Casdoor subject (routinely a {@code provider:handle} composite carrying an
 * e-mail) into a URL. Two properties carry the whole design and are pinned here:
 * <ul>
 *   <li><b>minted once, never rotated</b> — a stored {@code characterImgRef} keeps
 *       resolving across profile edits and avatar re-uploads. This is enforced by the
 *       {@code avatar_ref IS NULL} predicate on the assign, not by convention;</li>
 *   <li><b>reverse-resolvable</b> — ref → pixels + owner + brand, so the serve route can
 *       make its access decision, with an unknown ref indistinguishable from a row that
 *       simply has no picture.</li>
 * </ul>
 */
@DataR2dbcTest
@Import({TestDatabaseConfig.class, UserProfileRepository.class})
class UserProfileRepositoryAvatarRefTest {

    /** 8-byte PNG signature — enough to prove BYTEA round-trips on the H2 slice. */
    private static final byte[] PNG =
            new byte[] {(byte) 0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a};

    /** The shape the serve route's charset gate accepts (lowercase-hex UUID). */
    private static final String UUID_SHAPE =
            "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}";

    @Autowired UserProfileRepository repo;
    @Autowired UserProfileR2dbcRepository raw;

    @BeforeEach void clean() { raw.deleteAll().block(); }
    @AfterEach  void wipe()  { raw.deleteAll().block(); }

    @Test
    void ensureAvatarRef_mintsAUuidShapedHandle_andIsStable() {
        repo.save(new UserProfile("alice", null, null, null, "Alice", "internal", false)).block();

        String first = repo.ensureAvatarRef("alice", "default").block();
        assertThat(first).isNotNull().matches(UUID_SHAPE);

        // Idempotent: asking again returns the SAME handle, never a fresh one.
        assertThat(repo.ensureAvatarRef("alice", "default").block()).isEqualTo(first);
    }

    @Test
    void ensureAvatarRef_survivesAvatarReuploadAndProfileEdit() {
        repo.save(new UserProfile("bob", null, null, null, "Bob", "internal", false)).block();
        repo.updateAvatarUrl("bob", "mxc://home/pic1", "default", PNG, "image/png").block();
        String ref = repo.ensureAvatarRef("bob", "default").block();

        // A new picture behind the SAME handle (the URL is stable; the pixels change —
        // which is exactly why the serve route is no-store), and an unrelated profile
        // edit must not disturb it either.
        repo.updateAvatarUrl("bob", "mxc://home/pic2", "default", PNG, "image/jpeg").block();
        repo.save(new UserProfile("bob", null, null, null, "Bob Edited", "internal", false)).block();

        assertThat(repo.ensureAvatarRef("bob", "default").block()).isEqualTo(ref);
        assertThat(repo.find("bob").block().displayName()).isEqualTo("Bob Edited");
        assertThat(repo.findAvatarBodyByRef(ref).block().contentType()).isEqualTo("image/jpeg");
    }

    @Test
    void ensureAvatarRef_noProfileRow_isEmpty() {
        assertThat(repo.ensureAvatarRef("nobody", "default").blockOptional()).isEmpty();
    }

    @Test
    void ensureAvatarRef_isPerOwner() {
        repo.save(new UserProfile("carol", null, null, null, "Carol", "internal", false)).block();
        repo.save(new UserProfile("dave", null, null, null, "Dave", "internal", false)).block();

        assertThat(repo.ensureAvatarRef("carol", "default").block())
                .isNotEqualTo(repo.ensureAvatarRef("dave", "default").block());
    }

    @Test
    void findAvatarBodyByRef_returnsPixelsWithOwnerAndBrand() {
        repo.save(new UserProfile("erin", null, null, null, "Erin", "internal", false)).block();
        repo.updateAvatarUrl("erin", "mxc://home/pic", "default", PNG, "image/png").block();
        String ref = repo.ensureAvatarRef("erin", "default").block();

        var body = repo.findAvatarBodyByRef(ref).block();
        assertThat(body).isNotNull();
        assertThat(body.bytes()).isEqualTo(PNG);
        assertThat(body.contentType()).isEqualTo("image/png");
        // owner + brand travel with the bytes: the serve route needs BOTH to decide, and
        // a cross-brand refusal has to look like an unknown ref, not like a 403.
        assertThat(body.owner()).isEqualTo("erin");
        assertThat(body.domain()).isEqualTo("default");
    }

    @Test
    void findAvatarBodyByRef_withNoStoredPixels_isEmpty() {
        // A handle can exist on a row that has no picture (the owner asked for one, then
        // deleted/never uploaded) — that must read as a miss, not as an empty image.
        repo.save(new UserProfile("frank", null, null, null, "Frank", "internal", false)).block();
        String ref = repo.ensureAvatarRef("frank", "default").block();

        assertThat(repo.findAvatarBodyByRef(ref).blockOptional()).isEmpty();
    }

    @Test
    void findAvatarBodyByRef_unknownOrBlank_isEmpty() {
        assertThat(repo.findAvatarBodyByRef("00000000-0000-0000-0000-000000000000")
                .blockOptional()).isEmpty();
        assertThat(repo.findAvatarBodyByRef("").blockOptional()).isEmpty();
        assertThat(repo.findAvatarBodyByRef(null).blockOptional()).isEmpty();
    }
}
