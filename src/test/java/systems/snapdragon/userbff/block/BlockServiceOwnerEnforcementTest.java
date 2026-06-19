package systems.snapdragon.userbff.block;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.data.r2dbc.DataR2dbcTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import systems.snapdragon.userbff.federation.FederationApiClient;
import systems.snapdragon.userbff.support.TestDatabaseConfig;
import systems.snapdragon.commons.web.ApiException;

import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * OWNER-ENFORCEMENT + best-effort-push test for {@link BlockService} over the real
 * repository slice. Asserts:
 * <ul>
 *   <li>a block is recorded under the CALLER (owner = passed subject) and listed
 *       only for that owner;</li>
 *   <li>{@code unblock} is owner+id scoped — a user cannot delete another's block
 *       even with the exact id;</li>
 *   <li>the external push is best-effort (STUB clients return false; the durable
 *       row stands).</li>
 * </ul>
 */
@DataR2dbcTest
@Import({TestDatabaseConfig.class, UserBlockRepository.class,
        BlockServiceOwnerEnforcementTest.Stubs.class})
class BlockServiceOwnerEnforcementTest {

    @TestConfiguration(proxyBeanMethods = false)
    static class Stubs {
        @Bean MatrixBlockClient matrix() { return new MatrixBlockClient(null); }      // stub
        @Bean MastodonBlockClient mastodon() { return new MastodonBlockClient(null); } // stub
        /** A federation client whose every call returns a canned moderation response. */
        @Bean FederationApiClient federation() {
            ExchangeFunction ef = req -> Mono.just(org.springframework.web.reactive.function.client.ClientResponse
                    .create(org.springframework.http.HttpStatus.OK)
                    .header("Content-Type", "application/json")
                    .body("{\"id\":1,\"kind\":\"instance-block\",\"status\":\"recommended\"}").build());
            return new FederationApiClient(WebClient.builder().exchangeFunction(ef).build());
        }
        @Bean BlockService blockService(UserBlockRepository repo, List<ExternalBlockClient> clients,
                                        FederationApiClient fed) {
            return new BlockService(repo, clients, fed);
        }
    }

    @Autowired BlockService service;
    @Autowired UserBlockRepository repo;

    /** A caller holding both homeserver platform roles (so the platform-role gate
     *  passes and these owner-enforcement assertions exercise the row logic). */
    private static final Set<String> BOTH_PLATFORM_ROLES =
            Set.of("ROLE_USER", "ROLE_MATRIX", "ROLE_MASTODON");

    // NOTE: @DataR2dbcTest reuses one H2 store across the methods of this class, so
    // assertions are scoped by a per-test unique target/owner rather than absolute
    // counts (which would be coupled across methods).

    @Test
    void block_recordedUnderCaller_pushIsBestEffortStub() {
        String target = "@spammer-bre1:evil";
        Map<String, Object> out = service.block("alice", target, "matrix", BOTH_PLATFORM_ROLES).block();
        assertThat(out).containsEntry("pushed", false).containsEntry("external", "stubbed");
        UserBlock b = (UserBlock) out.get("block");
        assertThat(b.userId()).isEqualTo("alice");
        // recorded for alice; never leaks to bob
        assertThat(service.list("alice").collectList().block())
                .anySatisfy(x -> assertThat(x.target()).isEqualTo(target));
        assertThat(service.list("bob").collectList().block())
                .noneSatisfy(x -> assertThat(x.target()).isEqualTo(target));
    }

    @Test
    void internalPlatform_noExternalPush() {
        // internal needs only the ROLE_USER floor — no platform role required.
        Map<String, Object> out = service.block("alice", "someone-int", "internal", Set.of("ROLE_USER")).block();
        assertThat(out).containsEntry("pushed", false).containsEntry("external", "n/a");
    }

    @Test
    void unblock_isOwnerAndIdScoped() {
        UserBlock aliceBlock = (UserBlock) service.block("alice", "@x-unb:evil", "matrix", BOTH_PLATFORM_ROLES)
                .block().get("block");
        // bob cannot delete alice's block (owner+id scoped)
        assertThatThrownBy(() -> service.unblock("bob", aliceBlock.id()).block())
                .isInstanceOf(ApiException.class);
        assertThat(service.list("alice").collectList().block())
                .anySatisfy(x -> assertThat(x.id()).isEqualTo(aliceBlock.id()));
        // alice can
        service.unblock("alice", aliceBlock.id()).block();
        assertThat(service.list("alice").collectList().block())
                .noneSatisfy(x -> assertThat(x.id()).isEqualTo(aliceBlock.id()));
    }

    @Test
    void block_rejectsBadPlatform() {
        assertThatThrownBy(() -> service.block("alice", "x", "telegram", BOTH_PLATFORM_ROLES).block())
                .isInstanceOf(ApiException.class);
    }

    // ── platform-role gate (service leg / defence-in-depth) ──────────────────

    @Test
    void block_matrixWithoutRoleMatrix_isForbidden() {
        // A caller with only the ROLE_USER floor (no ROLE_MATRIX) cannot matrix-block.
        ApiException ex = catchApiException(() -> service.block("alice", "@x:evil", "matrix", Set.of("ROLE_USER")).block());
        assertThat(ex.status().value()).isEqualTo(403);
    }

    @Test
    void block_mastodonWithoutRoleMastodon_isForbidden() {
        ApiException ex = catchApiException(() -> service.block("alice", "@x@evil", "mastodon", Set.of("ROLE_USER")).block());
        assertThat(ex.status().value()).isEqualTo(403);
    }

    @Test
    void block_matrixWithRoleMatrix_isAllowed() {
        Map<String, Object> out = service.block("alice", "@ok:host", "matrix", Set.of("ROLE_USER", "ROLE_MATRIX")).block();
        assertThat(((UserBlock) out.get("block")).platform()).isEqualTo("matrix");
    }

    @Test
    void recommendInstanceBlock_delegatesToFederation() {
        Map<String, Object> out = service.recommendInstanceBlock("alice", "evil.example", "spam", BOTH_PLATFORM_ROLES).block();
        assertThat(out).containsEntry("recommended", true).containsEntry("instance", "evil.example");
    }

    @Test
    void recommendInstanceBlock_withoutAnyPlatformRole_isForbidden() {
        ApiException ex = catchApiException(
                () -> service.recommendInstanceBlock("alice", "evil.example", "spam", Set.of("ROLE_USER")).block());
        assertThat(ex.status().value()).isEqualTo(403);
    }

    private static ApiException catchApiException(Runnable r) {
        try {
            r.run();
        } catch (ApiException e) {
            return e;
        }
        throw new AssertionError("expected an ApiException to be thrown");
    }
}
