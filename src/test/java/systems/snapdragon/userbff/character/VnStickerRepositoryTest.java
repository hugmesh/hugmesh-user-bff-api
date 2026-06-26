package systems.snapdragon.userbff.character;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.context.annotation.Import;
import systems.snapdragon.commons.testsupport.PostgresTestSupport;
import systems.snapdragon.userbff.support.PostgresSliceTestConfig;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * R2DBC slice test for {@link VnStickerRepository} against Testcontainers-Postgres with
 * the REAL Liquibase changelog (incl. 017). Postgres (not H2) is REQUIRED: the table's id
 * is a {@code (gen_random_uuid())::text} column DEFAULT and the INSERT uses
 * {@code RETURNING id}, neither of which H2 honours. Verifies the save round-trip
 * (DB-generated id, status=PENDING, mxc:// + expression persisted), the owner+domain-
 * scoped list, and owner-scoped single read (a foreign owner yields empty — the 404 source).
 *
 * <p>NOTE: {@code @DataR2dbcTest} reuses ONE container store across the methods of this
 * class, so each method uses a UNIQUE owner id to stay isolated.
 */
@DataR2dbcTest
@ActiveProfiles("test")
@Import({PostgresSliceTestConfig.class, VnStickerRepository.class})
class VnStickerRepositoryTest extends PostgresTestSupport {

    @Autowired VnStickerRepository repo;

    private static final String MXC = "mxc://home.invalid/abc123";

    @Test
    void save_thenListAndFindOwned_ownerScoped() {
        assertThat(repo.listForOwner("alice", "default").collectList().block()).isEmpty();

        VnSticker saved = repo.save("alice", "default", "happy", MXC, "PENDING").block();
        assertThat(saved).isNotNull();
        assertThat(saved.id()).isNotBlank();
        assertThat(saved.ownerSubject()).isEqualTo("alice");
        assertThat(saved.domain()).isEqualTo("default");
        assertThat(saved.expression()).isEqualTo("happy");
        assertThat(saved.mxcUrl()).isEqualTo(MXC);
        assertThat(saved.status()).isEqualTo("PENDING");
        assertThat(saved.createdAt()).isNotNull();

        // alice reads her own sticker by id; bob (a different owner) does not.
        assertThat(repo.findOwned(saved.id(), "alice").block()).isNotNull();
        assertThat(repo.findOwned(saved.id(), "bob").blockOptional()).isEmpty();

        assertThat(repo.listForOwner("alice", "default").collectList().block()).hasSize(1);
    }

    @Test
    void save_allCanonicalExpressions_persist() {
        // every canonical expression passes the 017 CHECK constraint.
        for (String expr : StickerExpression.ALL) {
            VnSticker saved = repo.save("expr-owner", "default", expr, MXC, "PENDING").block();
            assertThat(saved).isNotNull();
            assertThat(saved.expression()).isEqualTo(expr);
        }
        assertThat(repo.listForOwner("expr-owner", "default").collectList().block())
                .hasSize(StickerExpression.ALL.size());
    }

    // ── 018 finding_id capture + status flip ─────────────────────────────────

    @Test
    void setFindingId_stampsOwnerScoped_thenReadable() {
        VnSticker saved = repo.save("fid-st-owner", "default", "happy", MXC, "PENDING").block();
        assertThat(saved).isNotNull();
        assertThat(saved.findingId()).isNull();   // null on insert

        // a stamp for the WRONG owner touches nothing (owner-scoped); the right owner = 1 row.
        assertThat(repo.setFindingId(saved.id(), "someone-else", 99L).block()).isZero();
        assertThat(repo.setFindingId(saved.id(), "fid-st-owner", 7L).block()).isEqualTo(1);

        assertThat(repo.findOwned(saved.id(), "fid-st-owner").block().findingId()).isEqualTo(7L);
    }

    @Test
    void updateStatusByIdWherePending_flipsPendingToActive_andIsIdempotent() {
        VnSticker saved = repo.save("st-flip-active", "default", "happy", MXC, "PENDING").block();
        assertThat(saved).isNotNull();

        // first flip: PENDING -> ACTIVE (1 row).
        assertThat(repo.updateStatusByIdWherePending(saved.id(), "ACTIVE").block()).isEqualTo(1);
        assertThat(repo.findOwned(saved.id(), "st-flip-active").block().status()).isEqualTo("ACTIVE");

        // second flip on the now-ACTIVE row: 0 rows (the PENDING guard) — idempotent no-op.
        assertThat(repo.updateStatusByIdWherePending(saved.id(), "REJECTED").block()).isZero();
        assertThat(repo.findOwned(saved.id(), "st-flip-active").block().status()).isEqualTo("ACTIVE");
    }

    @Test
    void updateStatusByIdWherePending_flipsPendingToRejected() {
        VnSticker saved = repo.save("st-flip-reject", "default", "sad", MXC, "PENDING").block();
        assertThat(repo.updateStatusByIdWherePending(saved.id(), "REJECTED").block()).isEqualTo(1);
        assertThat(repo.findOwned(saved.id(), "st-flip-reject").block().status()).isEqualTo("REJECTED");
    }

    @Test
    void updateStatusByIdWherePending_unknownId_isZeroRows_noOp() {
        assertThat(repo.updateStatusByIdWherePending("no-such-sticker-id", "ACTIVE").block()).isZero();
    }

    @Nested
    class DomainScope {
        @Test
        void sameOwnerTwoBrands_listsOwnBrandOnly() {
            repo.save("st-ms", "brandx", "happy", MXC, "PENDING").block();
            repo.save("st-ms", "brandy", "sad", MXC, "PENDING").block();

            assertThat(repo.listForOwner("st-ms", "brandx").collectList().block())
                    .extracting(VnSticker::expression).containsExactly("happy");
            assertThat(repo.listForOwner("st-ms", "brandy").collectList().block())
                    .extracting(VnSticker::expression).containsExactly("sad");
        }

        @Test
        void superadminBypass_seesAnyBrandSticker() {
            repo.save("st-sa", "brandy", "smug", MXC, "PENDING").block();
            // null domain = SUPERADMIN bypass -> the brandy sticker is visible.
            assertThat(repo.listForOwner("st-sa", null).collectList().block())
                    .extracting(VnSticker::expression).containsExactly("smug");
        }
    }
}
