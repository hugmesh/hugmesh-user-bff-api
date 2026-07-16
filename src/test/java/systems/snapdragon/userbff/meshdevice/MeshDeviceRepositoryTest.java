package systems.snapdragon.userbff.meshdevice;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.test.context.ActiveProfiles;
import systems.snapdragon.commons.testsupport.PostgresTestSupport;
import systems.snapdragon.commons.web.ApiException;
import systems.snapdragon.userbff.support.PostgresSliceTestConfig;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.catchThrowable;

/**
 * R2DBC slice test for {@link MeshDeviceRepository} (+ the {@link MeshDeviceService}
 * semantics that only mean anything over the REAL constraints) against
 * Testcontainers-Postgres with the REAL Liquibase changelog (incl. 019). Postgres (not
 * H2) is REQUIRED: the table's id is a {@code (gen_random_uuid())::text} column DEFAULT,
 * the INSERT uses {@code RETURNING id}, and the canonical-node-id regex CHECK is
 * Postgres-gated. Verifies:
 *
 * <ul>
 *   <li>the claim round-trip (DB-generated id, DEFAULT visibility=private /
 *       state=active, NULL status columns) + the owner+domain-scoped list;</li>
 *   <li>GLOBAL node-id uniqueness — a second claim of the same node id by a DIFFERENT
 *       owner in a DIFFERENT domain is a DuplicateKeyException (one owner per radio),
 *       which the service maps to a 409;</li>
 *   <li>release is owner-scoped (a foreign owner deletes ZERO rows) and domain-scoped;</li>
 *   <li>the 019 CHECKs hold (canonical node-id shape; battery 0..101);</li>
 *   <li>REVOKED-row semantics: excluded from the bridge export, visibility write is a
 *       guarded no-op, the node id stays UNCLAIMABLE while the row exists, and an
 *       owner delete frees it (the documented trade-off);</li>
 *   <li>the bridge status write-back only touches ACTIVE rows (unknown node ids are the
 *       fail-soft zero-rows leg).</li>
 * </ul>
 *
 * <p>NOTE: {@code @DataR2dbcTest} reuses ONE container store across the methods of this
 * class, so each method uses UNIQUE owner ids AND node ids to stay isolated.
 */
@DataR2dbcTest
@ActiveProfiles("test")
@Import({PostgresSliceTestConfig.class, MeshDeviceRepository.class})
class MeshDeviceRepositoryTest extends PostgresTestSupport {

    @Autowired MeshDeviceRepository repo;
    @Autowired DatabaseClient db;

    /** The service under test where the semantics live above the repo (normalization,
     *  duplicate→409, visibility diagnose); plain construction — its only collaborator
     *  is the repository this slice provides. */
    MeshDeviceService service;

    @BeforeEach
    void setUpService() {
        service = new MeshDeviceService(repo);
    }

    /** Flip a row to REVOKED directly in the store — the mod-bff revocation WRITER is a
     *  later wave, so tests stage revoked rows the way that writer eventually will. */
    private void revoke(String id) {
        db.sql("UPDATE mesh_device SET state = 'revoked', revoked_by = 'mod-x', "
                        + "revoked_at = now(), revoke_reason = 'spoofing traffic' WHERE id = :id")
                .bind("id", id)
                .fetch().rowsUpdated().block();
    }

    // ── claim + list (owner-scoped) ───────────────────────────────────────────

    @Test
    void claim_thenList_ownerScoped_withDefaults() {
        assertThat(repo.listForOwner("mesh-alice", "default").collectList().block()).isEmpty();

        MeshDevice saved = repo.save("mesh-alice", "default", "!a1b2c3d4", "field radio").block();
        assertThat(saved).isNotNull();
        assertThat(saved.id()).isNotBlank();
        assertThat(saved.nodeId()).isEqualTo("!a1b2c3d4");
        assertThat(saved.label()).isEqualTo("field radio");
        // 019 column DEFAULTs: a fresh claim is private + active, never seen yet.
        assertThat(saved.visibility()).isEqualTo("private");
        assertThat(saved.state()).isEqualTo("active");
        assertThat(saved.revokeReason()).isNull();
        assertThat(saved.revokedAt()).isNull();
        assertThat(saved.lastSeenAt()).isNull();
        assertThat(saved.batteryPct()).isNull();
        assertThat(saved.snr()).isNull();
        assertThat(saved.hopsAway()).isNull();
        assertThat(saved.viaDevice()).isNull();
        assertThat(saved.createdAt()).isNotNull();

        // alice reads her own device by id; bob (a different owner) does not.
        assertThat(repo.findOwned(saved.id(), "mesh-alice").block()).isNotNull();
        assertThat(repo.findOwned(saved.id(), "mesh-bob").blockOptional()).isEmpty();

        assertThat(repo.listForOwner("mesh-alice", "default").collectList().block()).hasSize(1);
        assertThat(repo.listForOwner("mesh-bob", "default").collectList().block()).isEmpty();
    }

    @Test
    void claim_nullLabel_persistsAsNull() {
        MeshDevice saved = repo.save("mesh-carol", "default", "!00000001", null).block();
        assertThat(saved).isNotNull();
        assertThat(saved.label()).isNull();
    }

    // ── GLOBAL uniqueness (one owner per radio) ───────────────────────────────

    @Test
    void secondClaimOfSameNodeId_differentOwnerAndDomain_isDuplicateKey() {
        repo.save("uniq-a", "brandx", "!0000aaaa", null).block();
        // The 019 unique constraint is on node_id ALONE — a different owner in a
        // DIFFERENT brand still collides: one owner per radio, platform-wide.
        assertThatThrownBy(() -> repo.save("uniq-b", "brandy", "!0000aaaa", null).block())
                .isInstanceOf(DuplicateKeyException.class);
    }

    @Test
    void service_mapsDuplicateClaimTo409Conflict() {
        service.claim("conf-a", "default", "!0000bbbb", null).block();
        Throwable t = catchThrowable(() -> service.claim("conf-b", "default", "!0000bbbb", null).block());
        assertThat(t).isInstanceOf(ApiException.class);
        assertThat(((ApiException) t).status().value()).isEqualTo(409);
    }

    @Test
    void service_normalizesClaimedNodeId_beforeStorage() {
        // bare uppercase in → canonical "!"+lowercase stored (the 019 CHECK would
        // reject anything else).
        MeshDevice saved = service.claim("norm-owner", "default", "A1B2C3DF", "  cased  ").block();
        assertThat(saved).isNotNull();
        assertThat(saved.nodeId()).isEqualTo("!a1b2c3df");
        assertThat(saved.label()).isEqualTo("cased");   // trimmed

        // the "!"-prefixed uppercase shape collides with its OWN canonical form.
        Throwable t = catchThrowable(() -> service.claim("norm-other", "default", "!A1B2C3DF", null).block());
        assertThat(t).isInstanceOf(ApiException.class);
        assertThat(((ApiException) t).status().value()).isEqualTo(409);
    }

    // ── 019 CHECK parity ──────────────────────────────────────────────────────

    @Test
    void nonCanonicalNodeId_isRejectedByTheShapeCheck() {
        // The repository layer takes the node id as-given (the service normalizes);
        // an un-normalized value must be stopped by the 019 regex CHECK backstop.
        assertThatThrownBy(() -> repo.save("chk-owner", "default", "!ABCD1234", null).block())
                .isInstanceOf(DataIntegrityViolationException.class);
    }

    @Test
    void outOfRangeBattery_isRejectedByTheBatteryCheck() {
        MeshDevice saved = repo.save("bat-owner", "default", "!ddddeeee", null).block();
        assertThat(saved).isNotNull();
        // The service CLAMPS bridge telemetry to 0..101 before the update; a raw
        // out-of-range write is stopped by the DB backstop.
        assertThatThrownBy(() -> repo.applyStatusWhereActive(
                        "!ddddeeee", Instant.now(), 150, null, null, null).block())
                .isInstanceOf(DataIntegrityViolationException.class);
    }

    // ── release (owner + domain scoped) ───────────────────────────────────────

    @Test
    void release_onlyMine() {
        MeshDevice saved = repo.save("rel-owner", "default", "!11112222", null).block();
        assertThat(saved).isNotNull();

        // an intruder (wrong owner, right id) deletes ZERO rows; the row stands.
        assertThat(repo.delete(saved.id(), "rel-intruder", "default").block()).isZero();
        assertThat(repo.listForOwner("rel-owner", "default").collectList().block()).hasSize(1);

        // the owner releases it.
        assertThat(repo.delete(saved.id(), "rel-owner", "default").block()).isEqualTo(1);
        assertThat(repo.listForOwner("rel-owner", "default").collectList().block()).isEmpty();
    }

    @Test
    void release_isDomainScoped_nullDomainIsSuperadminBypass() {
        MeshDevice saved = repo.save("rel-brand", "brandx", "!33334444", null).block();
        assertThat(saved).isNotNull();

        // wrong brand deletes ZERO rows even for the right owner+id …
        assertThat(repo.delete(saved.id(), "rel-brand", "brandy").block()).isZero();
        // … the SUPERADMIN unscoped leg (null domain) reaches it.
        assertThat(repo.delete(saved.id(), "rel-brand", null).block()).isEqualTo(1);
    }

    // ── visibility (owner-managed, ACTIVE-guarded) ────────────────────────────

    @Test
    void setVisibility_ownerScoped_activeRow() {
        MeshDevice saved = repo.save("vis-owner", "default", "!55556666", null).block();
        assertThat(saved).isNotNull();

        // a foreign owner updates ZERO rows (owner predicate).
        assertThat(repo.setVisibilityWhereActive(saved.id(), "vis-intruder", "friends").block()).isZero();
        // the owner flips it.
        assertThat(repo.setVisibilityWhereActive(saved.id(), "vis-owner", "friends").block()).isEqualTo(1);
        assertThat(repo.findOwned(saved.id(), "vis-owner").block().visibility()).isEqualTo("friends");
    }

    @Test
    void service_setVisibility_unknownOrForeignId_is404() {
        Throwable t = catchThrowable(() ->
                service.setVisibility("vis-nobody", "no-such-id", "default", "friends").block());
        assertThat(t).isInstanceOf(ApiException.class);
        assertThat(((ApiException) t).status().value()).isEqualTo(404);
    }

    // ── REVOKED-row semantics ─────────────────────────────────────────────────

    @Test
    void revokedRow_visibilityFrozen_409_butStillListedWithReason() {
        MeshDevice saved = repo.save("rev-owner", "default", "!7777888a", null).block();
        assertThat(saved).isNotNull();
        revoke(saved.id());

        // the ACTIVE guard makes the write a no-op …
        assertThat(repo.setVisibilityWhereActive(saved.id(), "rev-owner", "channels").block()).isZero();
        // … which the service diagnoses as a 409 (the row exists and is the caller's).
        Throwable t = catchThrowable(() ->
                service.setVisibility("rev-owner", saved.id(), "default", "channels").block());
        assertThat(t).isInstanceOf(ApiException.class);
        assertThat(((ApiException) t).status().value()).isEqualTo(409);

        // the owner still SEES the row, with the state + user-facing reason.
        MeshDevice mine = repo.listForOwner("rev-owner", "default").blockFirst();
        assertThat(mine.state()).isEqualTo("revoked");
        assertThat(mine.revokeReason()).isEqualTo("spoofing traffic");
        assertThat(mine.revokedAt()).isNotNull();
    }

    @Test
    void revokedRow_excludedFromBridgeExport() {
        MeshDevice active = repo.save("bridge-a", "default", "!0a0a0a0a", null).block();
        MeshDevice revoked = repo.save("bridge-b", "default", "!0b0b0b0b", null).block();
        revoke(revoked.id());

        var exported = repo.listActiveForBridge()
                .filter(e -> "bridge-a".equals(e.ownerSubject()) || "bridge-b".equals(e.ownerSubject()))
                .collectList().block();
        assertThat(exported).extracting(MeshDeviceEntity::nodeId).containsExactly("!0a0a0a0a");
        // the export carries the owner subject (what the internal controller resolves
        // to a localpart) — the field the user-facing wire shape deliberately omits.
        assertThat(exported.getFirst().ownerSubject()).isEqualTo("bridge-a");
        assertThat(active).isNotNull();
    }

    @Test
    void revokedNodeId_cannotBeReclaimed_untilOwnerReleasesIt() {
        MeshDevice saved = repo.save("recl-owner", "default", "!feedbeef", null).block();
        assertThat(saved).isNotNull();
        revoke(saved.id());

        // While the revoked row exists the node id stays occupied — a re-claim by
        // ANYONE (including the original owner under a new row) is a 409: revocation
        // is not circumventable by re-claiming.
        Throwable t = catchThrowable(() -> service.claim("recl-other", "default", "!feedbeef", null).block());
        assertThat(t).isInstanceOf(ApiException.class);
        assertThat(((ApiException) t).status().value()).isEqualTo(409);

        // The owner MAY release the revoked row (deliberately not state-gated) — which
        // FREES the node id (the documented trade-off for the moderation wave).
        assertThat(repo.delete(saved.id(), "recl-owner", "default").block()).isEqualTo(1);
        assertThat(service.claim("recl-other", "default", "!feedbeef", null).block()).isNotNull();
    }

    // ── bridge status write-back (ACTIVE-guarded, fail-soft) ──────────────────

    @Test
    void applyStatus_updatesActiveRow_ignoresUnknown_andRevoked() {
        MeshDevice active = repo.save("stat-owner", "default", "!9999aaaa", null).block();
        MeshDevice revoked = repo.save("stat-owner", "default", "!bbbbcccc", null).block();
        revoke(revoked.id());

        Instant seen = Instant.now();
        // ACTIVE row: one row updated, all five fields land.
        assertThat(repo.applyStatusWhereActive("!9999aaaa", seen, 87, 7.5, 2, "!aabbccdd").block())
                .isEqualTo(1);
        MeshDevice read = repo.findOwned(active.id(), "stat-owner").block();
        assertThat(read.lastSeenAt()).isNotNull();
        assertThat(read.batteryPct()).isEqualTo(87);
        assertThat(read.snr()).isEqualTo(7.5);
        assertThat(read.hopsAway()).isEqualTo(2);
        assertThat(read.viaDevice()).isEqualTo("!aabbccdd");

        // unknown node id / revoked row: ZERO rows — the batch endpoint's fail-soft
        // "ignored" leg.
        assertThat(repo.applyStatusWhereActive("!eeeeeeee", seen, 50, null, null, null).block()).isZero();
        assertThat(repo.applyStatusWhereActive("!bbbbcccc", seen, 50, null, null, null).block()).isZero();
        assertThat(repo.findOwned(revoked.id(), "stat-owner").block().batteryPct()).isNull();
    }

    @Test
    void service_applyStatus_clampsAndNormalizes() {
        repo.save("clamp-owner", "default", "!12ab34cd", null).block();

        // uppercase/bare node id in, battery over the Meshtastic 101 cap, negative
        // hops, over-long via — clamped/normalized, never dropped or errored.
        Boolean updated = service.applyStatus("12AB34CD", null, 150, -3.25, -2,
                "x".repeat(80)).block();
        assertThat(updated).isTrue();

        MeshDevice read = repo.listForOwner("clamp-owner", "default").blockFirst();
        assertThat(read.batteryPct()).isEqualTo(101);
        assertThat(read.hopsAway()).isZero();
        assertThat(read.snr()).isEqualTo(-3.25);
        assertThat(read.lastSeenAt()).isNotNull();          // defaulted to now()
        assertThat(read.viaDevice()).hasSize(64);           // truncated to the column
    }

    @Test
    void service_applyStatus_malformedNodeId_isIgnoredNotError() {
        assertThat(service.applyStatus("not-a-node", null, 50, null, null, null).block()).isFalse();
        assertThat(service.applyStatus(null, null, 50, null, null, null).block()).isFalse();
    }

    // ── domain scoping ────────────────────────────────────────────────────────

    @Nested
    class DomainScope {
        @Test
        void sameOwnerTwoBrands_listsOwnBrandOnly() {
            repo.save("md-ms", "brandx", "!c0ffee00", "x-radio").block();
            repo.save("md-ms", "brandy", "!c0ffee11", "y-radio").block();

            assertThat(repo.listForOwner("md-ms", "brandx").collectList().block())
                    .extracting(MeshDevice::label).containsExactly("x-radio");
            assertThat(repo.listForOwner("md-ms", "brandy").collectList().block())
                    .extracting(MeshDevice::label).containsExactly("y-radio");
        }

        @Test
        void superadminBypass_seesAnyBrandDevice() {
            repo.save("md-sa", "brandy", "!c0ffee22", "only-radio").block();
            // null domain = SUPERADMIN bypass -> the brandy device is visible.
            assertThat(repo.listForOwner("md-sa", null).collectList().block())
                    .extracting(MeshDevice::label).containsExactly("only-radio");
        }
    }
}
