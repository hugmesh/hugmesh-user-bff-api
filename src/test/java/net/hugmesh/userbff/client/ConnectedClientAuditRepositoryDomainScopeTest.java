package net.hugmesh.userbff.client;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import reactor.core.publisher.Flux;
import reactor.test.StepVerifier;
import org.springframework.test.context.ActiveProfiles;
import net.hugmesh.commons.testsupport.PostgresTestSupport;
import net.hugmesh.userbff.support.PostgresSliceTestConfig;

import java.time.Duration;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * DOMAIN-SCOPE isolation at the SQL layer for {@link ConnectedClientAuditRepository}
 * against H2 (PostgreSQL-compat) with the REAL Liquibase changelog (incl.
 * 010-domain-scoping). Delineated per the test standard:
 *
 * <ul>
 *   <li><b>MULTIUSER-SITUATIONAL</b> — the SAME owner id recording clients in two
 *       brands sees only their own brand's rows; the SUPERADMIN bypass (null domain)
 *       sees both.</li>
 *   <li><b>CROSS-USER</b> — the ISOLATION KEYSTONE: a brand-X principal is DENIED
 *       brand-Y data (list/find returns nothing, revoke affects zero rows) even with a
 *       known row id; the brand-Y row is untouched.</li>
 *   <li><b>CONCURRENT</b> — two brands recording clients under the same owner id at
 *       once each land in their own brand; a cross-brand revoke race never removes the
 *       other brand's active client.</li>
 * </ul>
 *
 * <p>NOTE: {@code @DataR2dbcTest} reuses ONE H2 store across the methods of this
 * class, so each method uses a UNIQUE owner id to stay isolated from the others
 * (the same convention as {@code UserBlockRepositoryDomainScopeTest}).
 */
@DataR2dbcTest
@ActiveProfiles("test")
@Import({PostgresSliceTestConfig.class, ConnectedClientAuditRepository.class})
class ConnectedClientAuditRepositoryDomainScopeTest extends PostgresTestSupport {

    @Autowired ConnectedClientAuditRepository repo;

    // ── MULTIUSER-SITUATIONAL ─────────────────────────────────────────────────
    @Nested
    class MultiuserSituational {

        @Test
        void sameOwnerInTwoBrands_eachSeesOnlyOwnBrand() {
            repo.record("ms-1", "matrix", ConnectedClient.KIND_DEVICE, "DEV-X", "Element", "brandx").block();
            repo.record("ms-1", "mastodon", ConnectedClient.KIND_OAUTH_APP, "APP-Y", "Tusky", "brandy").block();

            List<ConnectedClient> x = repo.listForOwner("ms-1", "brandx").collectList().block();
            List<ConnectedClient> y = repo.listForOwner("ms-1", "brandy").collectList().block();
            assertThat(x).extracting(ConnectedClient::externalRef).containsExactly("DEV-X");
            assertThat(y).extracting(ConnectedClient::externalRef).containsExactly("APP-Y");
        }

        @Test
        void superadminBypass_nullDomain_seesEveryBrand() {
            repo.record("ms-2", "matrix", ConnectedClient.KIND_DEVICE, "DEV-X2", "Element", "brandx").block();
            repo.record("ms-2", "mastodon", ConnectedClient.KIND_OAUTH_APP, "APP-Y2", "Ivory", "brandy").block();

            // null domain = SUPERADMIN cross-domain bypass -> both rows.
            List<ConnectedClient> all = repo.listForOwner("ms-2", null).collectList().block();
            assertThat(all).extracting(ConnectedClient::externalRef)
                    .containsExactlyInAnyOrder("DEV-X2", "APP-Y2");
        }
    }

    // ── CROSS-USER (isolation keystone) ───────────────────────────────────────
    @Nested
    class CrossUser {

        @Test
        void brandXPrincipal_cannotReadBrandYRow() {
            ConnectedClient yRow = repo.record("cu-1", "mastodon", ConnectedClient.KIND_OAUTH_APP,
                    "APP-CU1", "Tusky", "brandy").block();
            // cu-1 acting from brandx sees nothing of their brandy client.
            assertThat(repo.listForOwner("cu-1", "brandx").collectList().block()).isEmpty();
            assertThat(repo.find("cu-1", yRow.id(), "brandx").blockOptional()).isEmpty();
            // brandy still has it.
            assertThat(repo.find("cu-1", yRow.id(), "brandy").block()).isNotNull();
        }

        @Test
        void brandXPrincipal_cannotRevokeBrandYRow_evenWithKnownId() {
            ConnectedClient yRow = repo.record("cu-2", "mastodon", ConnectedClient.KIND_OAUTH_APP,
                    "APP-CU2", "Tusky", "brandy").block();
            // a revoke scoped to brandx (the caller's brand) with the brandy row id
            // affects ZERO rows — the cross-brand row is untouched.
            assertThat(repo.revoke("cu-2", yRow.id(), "brandx").block()).isEqualTo(0L);
            assertThat(repo.find("cu-2", yRow.id(), "brandy").block().active()).isTrue();
            // the legitimate brandy-scoped revoke works.
            assertThat(repo.revoke("cu-2", yRow.id(), "brandy").block()).isEqualTo(1L);
        }

        @Test
        void differentOwners_sameBrand_stillOwnerIsolated() {
            ConnectedClient aRow = repo.record("cu-3a", "matrix", ConnectedClient.KIND_DEVICE,
                    "DEV-CU3A", "Element", "brandx").block();
            repo.record("cu-3b", "matrix", ConnectedClient.KIND_DEVICE, "DEV-CU3B", "Cinny", "brandx").block();
            // cu-3b (same brand) cannot revoke cu-3a's client.
            assertThat(repo.revoke("cu-3b", aRow.id(), "brandx").block()).isEqualTo(0L);
            assertThat(repo.find("cu-3a", aRow.id(), "brandx").block().active()).isTrue();
        }
    }

    // ── CONCURRENT ────────────────────────────────────────────────────────────
    @Nested
    class Concurrent {

        @Test
        void concurrentCrossBrandRecords_sameOwner_landInOwnBrands() {
            // 10 records per brand under the SAME owner id, interleaved.
            Flux<ConnectedClient> x = Flux.range(0, 10)
                    .flatMap(i -> repo.record("co-1", "matrix", ConnectedClient.KIND_DEVICE,
                            "DEV-X" + i, "Element-" + i, "brandx"));
            Flux<ConnectedClient> y = Flux.range(0, 10)
                    .flatMap(i -> repo.record("co-1", "mastodon", ConnectedClient.KIND_OAUTH_APP,
                            "APP-Y" + i, "Tusky-" + i, "brandy"));
            Flux.merge(x, y).blockLast(Duration.ofSeconds(30));

            assertThat(repo.listForOwner("co-1", "brandx").collectList().block()).hasSize(10);
            assertThat(repo.listForOwner("co-1", "brandy").collectList().block()).hasSize(10);
            // and every brandx row really is brandx-scoped (none leaked to brandy view).
            assertThat(repo.listForOwner("co-1", "brandx").collectList().block())
                    .allSatisfy(c -> assertThat(c.externalRef()).startsWith("DEV-X"));
        }

        @Test
        void concurrentCrossBrandRevokes_neverRemoveOtherBrandRow() {
            ConnectedClient xRow = repo.record("co-2", "matrix", ConnectedClient.KIND_DEVICE,
                    "DEV-XCO2", "Element", "brandx").block();
            ConnectedClient yRow = repo.record("co-2", "mastodon", ConnectedClient.KIND_OAUTH_APP,
                    "APP-YCO2", "Tusky", "brandy").block();

            // brandx tries to revoke the brandy id AND brandy revokes its own, at once.
            Flux<Long> revokes = Flux.merge(
                    repo.revoke("co-2", yRow.id(), "brandx"),   // wrong brand -> 0
                    repo.revoke("co-2", yRow.id(), "brandy"));  // right brand -> 1
            StepVerifier.create(revokes.reduce(0L, (a, b) -> a + b))
                    .expectNext(1L)                               // exactly one effective revoke
                    .verifyComplete();
            // brandx row is wholly untouched by the cross-brand attempt.
            assertThat(repo.find("co-2", xRow.id(), "brandx").block().active()).isTrue();
        }
    }
}
