package systems.hugmesh.userbff.block;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import systems.hugmesh.userbff.federation.FederationApiClient;
import org.springframework.test.context.ActiveProfiles;
import systems.hugmesh.commons.testsupport.PostgresTestSupport;
import systems.hugmesh.userbff.support.PostgresSliceTestConfig;

import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * DOMAIN-SCOPE enforcement at the SERVICE layer for {@link BlockService} over the
 * real repository slice — proves owner-enforcement AND domain-scope COMPOSE (a
 * principal must satisfy BOTH). Delineated:
 *
 * <ul>
 *   <li><b>MULTIUSER-SITUATIONAL</b> — the same owner id in two brands lists only
 *       their own brand via the service.</li>
 *   <li><b>CROSS-USER</b> — a brand-X principal is DENIED brand-Y data through the
 *       service: list returns nothing, unblock 404s (zero rows), the brandY row
 *       stands. SUPERADMIN (null domain) sees both.</li>
 *   <li><b>CONCURRENT</b> — concurrent same-owner inserts across brands each land in
 *       their own brand.</li>
 * </ul>
 */
@DataR2dbcTest
@ActiveProfiles("test")
@Import({PostgresSliceTestConfig.class, UserBlockRepository.class,
        BlockServiceDomainScopeTest.Stubs.class})
class BlockServiceDomainScopeTest extends PostgresTestSupport {

    @TestConfiguration(proxyBeanMethods = false)
    static class Stubs {
        @Bean MatrixBlockClient matrix() { return new MatrixBlockClient(null); }
        @Bean MastodonBlockClient mastodon() { return new MastodonBlockClient(null); }
        @Bean FederationApiClient federation() {
            ExchangeFunction ef = req -> Mono.just(org.springframework.web.reactive.function.client.ClientResponse
                    .create(org.springframework.http.HttpStatus.OK)
                    .header("Content-Type", "application/json")
                    .body("{\"id\":1}").build());
            return new FederationApiClient(WebClient.builder().exchangeFunction(ef).build());
        }
        @Bean BlockService blockService(UserBlockRepository repo, List<ExternalBlockClient> clients,
                                        FederationApiClient fed) {
            return new BlockService(repo, clients, fed);
        }
    }

    @Autowired BlockService service;

    private static final Set<String> PLATFORM_ROLES =
            Set.of("ROLE_USER", "ROLE_MATRIX", "ROLE_MASTODON");

    // ── MULTIUSER-SITUATIONAL ─────────────────────────────────────────────────
    @Nested
    class MultiuserSituational {
        @Test
        void sameOwnerTwoBrands_listsOwnBrandOnly() {
            service.block("u1", "@x:evil", "matrix", "brandx", PLATFORM_ROLES).block();
            service.block("u1", "@y:evil", "mastodon", "brandy", PLATFORM_ROLES).block();

            assertThat(service.list("u1", "brandx").collectList().block())
                    .extracting(UserBlock::target).containsExactly("@x:evil");
            assertThat(service.list("u1", "brandy").collectList().block())
                    .extracting(UserBlock::target).containsExactly("@y:evil");
        }
    }

    // ── CROSS-USER ────────────────────────────────────────────────────────────
    @Nested
    class CrossUser {
        @Test
        void brandXPrincipal_deniedBrandYData() {
            var resultY = (java.util.Map<String, Object>)
                    service.block("u2", "@y:evil", "mastodon", "brandy", PLATFORM_ROLES).block();
            UserBlock yRow = (UserBlock) resultY.get("block");

            // u2 acting from brandx sees nothing of their brandy row.
            assertThat(service.list("u2", "brandx").collectList().block()).isEmpty();
            // an unblock scoped to brandx for the brandy row id 404s (zero rows).
            assertThatThrownBy(() -> service.unblock("u2", yRow.id(), "brandx").block())
                    .isInstanceOf(systems.hugmesh.commons.web.ApiException.class);
            // the brandy row stands and is reachable from brandy.
            assertThat(service.list("u2", "brandy").collectList().block()).hasSize(1);
        }

        @Test
        void superadminBypass_seesBothBrands() {
            service.block("u3", "@x:evil", "matrix", "brandx", PLATFORM_ROLES).block();
            service.block("u3", "@y:evil", "mastodon", "brandy", PLATFORM_ROLES).block();
            // null domain = SUPERADMIN cross-domain bypass.
            assertThat(service.list("u3", null).collectList().block())
                    .extracting(UserBlock::target).containsExactlyInAnyOrder("@x:evil", "@y:evil");
        }
    }

    // ── CONCURRENT ────────────────────────────────────────────────────────────
    @Nested
    class Concurrent {
        @Test
        void concurrentSameOwnerCrossBrandBlocks_landInOwnBrands() {
            reactor.core.publisher.Flux.merge(
                    reactor.core.publisher.Flux.range(0, 15).flatMap(i ->
                            service.block("u4", "@x" + i, "matrix", "brandx", PLATFORM_ROLES)),
                    reactor.core.publisher.Flux.range(0, 15).flatMap(i ->
                            service.block("u4", "@y" + i, "mastodon", "brandy", PLATFORM_ROLES)))
                    .blockLast(java.time.Duration.ofSeconds(30));

            assertThat(service.list("u4", "brandx").collectList().block()).hasSize(15);
            assertThat(service.list("u4", "brandy").collectList().block()).hasSize(15);
        }
    }
}
