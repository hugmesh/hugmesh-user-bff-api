package net.hugmesh.userbff.character;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;
import net.hugmesh.commons.testsupport.PostgresTestSupport;
import net.hugmesh.userbff.support.PostgresSliceTestConfig;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * R2DBC slice test for {@link VnCharacterPartRepository} against Testcontainers-Postgres
 * with the REAL Liquibase changelog (incl. 016). Postgres (not H2) is REQUIRED: the
 * table's id is a {@code (gen_random_uuid())::text} column DEFAULT and the INSERT uses
 * {@code RETURNING id} — neither of which H2 honours. Verifies the save round-trip
 * (DB-generated id, status=PENDING, SANITIZED svg persisted), the owner+domain-scoped
 * list, and owner-scoped single read (a foreign id/owner yields empty — the 404 source).
 *
 * <p>NOTE: {@code @DataR2dbcTest} reuses ONE container store across the methods of this
 * class, so each method uses a UNIQUE owner id to stay isolated.
 */
@DataR2dbcTest
@ActiveProfiles("test")
@Import({PostgresSliceTestConfig.class, VnCharacterPartRepository.class})
class VnCharacterPartRepositoryTest extends PostgresTestSupport {

    @Autowired VnCharacterPartRepository repo;

    private static final String SVG = "<svg xmlns=\"http://www.w3.org/2000/svg\"><path d=\"M0 0 L1 1\"/></svg>";

    @Test
    void save_thenListAndFindOwned_ownerScoped() {
        assertThat(repo.listForOwner("alice", "default").collectList().block()).isEmpty();

        VnCharacterPart saved = repo.save("alice", "default", "ear", SVG, "PENDING", "protogen").block();
        assertThat(saved).isNotNull();
        assertThat(saved.id()).isNotBlank();
        assertThat(saved.ownerSubject()).isEqualTo("alice");
        assertThat(saved.domain()).isEqualTo("default");
        assertThat(saved.name()).isEqualTo("ear");
        assertThat(saved.svg()).isEqualTo(SVG);
        assertThat(saved.status()).isEqualTo("PENDING");
        assertThat(saved.headArchetype()).isEqualTo("protogen");
        assertThat(saved.createdAt()).isNotNull();

        // alice reads her own part by id; bob (a different owner) does not.
        assertThat(repo.findOwned(saved.id(), "alice").block()).isNotNull();
        assertThat(repo.findOwned(saved.id(), "bob").blockOptional()).isEmpty();

        assertThat(repo.listForOwner("alice", "default").collectList().block()).hasSize(1);
    }

    @Test
    void save_nullableNameAndHeadArchetype_persistAsNull() {
        VnCharacterPart saved = repo.save("carol", "default", null, SVG, "PENDING", null).block();
        assertThat(saved).isNotNull();
        assertThat(saved.name()).isNull();
        assertThat(saved.headArchetype()).isNull();
        assertThat(saved.status()).isEqualTo("PENDING");
    }

    // ── 018 finding_id capture + status flip ─────────────────────────────────

    @Test
    void setFindingId_stampsOwnerScoped_thenReadable() {
        VnCharacterPart saved = repo.save("fid-owner", "default", null, SVG, "PENDING", null).block();
        assertThat(saved).isNotNull();
        assertThat(saved.findingId()).isNull();   // null on insert

        // a stamp for the WRONG owner touches nothing (owner-scoped); the right owner = 1 row.
        assertThat(repo.setFindingId(saved.id(), "someone-else", 99L).block()).isZero();
        assertThat(repo.setFindingId(saved.id(), "fid-owner", 4242L).block()).isEqualTo(1);

        assertThat(repo.findOwned(saved.id(), "fid-owner").block().findingId()).isEqualTo(4242L);
    }

    @Test
    void updateStatusByIdWherePending_flipsPendingToActive_andIsIdempotent() {
        VnCharacterPart saved = repo.save("flip-active", "default", null, SVG, "PENDING", null).block();
        assertThat(saved).isNotNull();

        // first flip: PENDING -> ACTIVE (1 row).
        assertThat(repo.updateStatusByIdWherePending(saved.id(), "ACTIVE").block()).isEqualTo(1);
        assertThat(repo.findOwned(saved.id(), "flip-active").block().status()).isEqualTo("ACTIVE");

        // second flip on the now-ACTIVE row: 0 rows (the PENDING guard) — idempotent no-op,
        // and it does NOT overwrite the resolved status.
        assertThat(repo.updateStatusByIdWherePending(saved.id(), "REJECTED").block()).isZero();
        assertThat(repo.findOwned(saved.id(), "flip-active").block().status()).isEqualTo("ACTIVE");
    }

    @Test
    void updateStatusByIdWherePending_flipsPendingToRejected() {
        VnCharacterPart saved = repo.save("flip-reject", "default", null, SVG, "PENDING", null).block();
        assertThat(repo.updateStatusByIdWherePending(saved.id(), "REJECTED").block()).isEqualTo(1);
        assertThat(repo.findOwned(saved.id(), "flip-reject").block().status()).isEqualTo("REJECTED");
    }

    @Test
    void updateStatusByIdWherePending_unknownId_isZeroRows_noOp() {
        assertThat(repo.updateStatusByIdWherePending("no-such-part-id", "ACTIVE").block()).isZero();
    }

    @Nested
    class DomainScope {
        @Test
        void sameOwnerTwoBrands_listsOwnBrandOnly() {
            repo.save("cp-ms", "brandx", "x-ear", SVG, "PENDING", null).block();
            repo.save("cp-ms", "brandy", "y-ear", SVG, "PENDING", null).block();

            assertThat(repo.listForOwner("cp-ms", "brandx").collectList().block())
                    .extracting(VnCharacterPart::name).containsExactly("x-ear");
            assertThat(repo.listForOwner("cp-ms", "brandy").collectList().block())
                    .extracting(VnCharacterPart::name).containsExactly("y-ear");
        }

        @Test
        void superadminBypass_seesAnyBrandPart() {
            repo.save("cp-sa", "brandy", "only-ear", SVG, "PENDING", null).block();
            // null domain = SUPERADMIN bypass -> the brandy part is visible.
            assertThat(repo.listForOwner("cp-sa", null).collectList().block())
                    .extracting(VnCharacterPart::name).containsExactly("only-ear");
        }
    }
}
