package systems.snapdragon.userbff.media;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.data.r2dbc.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import systems.snapdragon.userbff.support.TestDatabaseConfig;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * R2DBC slice test for {@link MediaPoisonDecisionRepository} against H2
 * (PostgreSQL-compat) with the REAL Liquibase changelog (incl. 007). Verifies the
 * record/list/find-by-ref round-trip AND owner-enforcement at the SQL layer: a user
 * only ever lists/finds their OWN decisions, and a nullable media_ref/backend persist
 * cleanly (bindNull). Mirrors UserBlockRepositoryTest.
 */
@DataR2dbcTest
@Import({TestDatabaseConfig.class, MediaPoisonDecisionRepository.class})
class MediaPoisonDecisionRepositoryTest {

    @Autowired MediaPoisonDecisionRepository repo;

    @Test
    void record_thenListAndFindByRef_ownerScoped() {
        assertThat(repo.listForOwner("alice").collectList().block()).isEmpty();

        MediaPoisonDecision saved = repo.record("alice", "mastodon", "media-123",
                "glaze", "protected", "cuda").block();
        assertThat(saved.id()).isNotBlank();
        assertThat(saved.userId()).isEqualTo("alice");
        assertThat(saved.platform()).isEqualTo("mastodon");
        assertThat(saved.mediaRef()).isEqualTo("media-123");
        assertThat(saved.mode()).isEqualTo("glaze");
        assertThat(saved.status()).isEqualTo("protected");
        assertThat(saved.backend()).isEqualTo("cuda");
        assertThat(saved.createdAt()).isNotNull();

        // alice finds her own decision by ref; bob (a different owner) does not.
        assertThat(repo.findByOwnerAndRef("alice", "media-123").block()).isNotNull();
        assertThat(repo.findByOwnerAndRef("bob", "media-123").blockOptional()).isEmpty();

        assertThat(repo.listForOwner("alice").collectList().block()).hasSize(1);
    }

    @Test
    void record_nullableMediaRefAndBackend_persistAsNull() {
        // a pre-upload failure / forward-through with no worker has null ref/backend.
        MediaPoisonDecision saved = repo.record("carol", "matrix", null,
                "none", "none", null).block();
        assertThat(saved.mediaRef()).isNull();
        assertThat(saved.backend()).isNull();
        assertThat(saved.status()).isEqualTo("none");
    }

    @Test
    void findByRef_returnsMostRecentForOwner() {
        repo.record("dave", "mastodon", "ref-x", "glaze", "skipped", "none").block();
        MediaPoisonDecision later = repo.record("dave", "mastodon", "ref-x",
                "glaze", "protected", "cuda").block();

        MediaPoisonDecision found = repo.findByOwnerAndRef("dave", "ref-x").block();
        assertThat(found).isNotNull();
        // newest first — the second (protected) write wins the badge.
        assertThat(found.id()).isEqualTo(later.id());
        assertThat(found.status()).isEqualTo("protected");
    }
}
