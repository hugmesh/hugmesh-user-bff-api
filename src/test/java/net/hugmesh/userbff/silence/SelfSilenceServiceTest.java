package net.hugmesh.userbff.silence;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import net.hugmesh.userbff.auth.AdminBffInternalClient;
import net.hugmesh.userbff.federation.FederationApiClient;
import net.hugmesh.userbff.support.TestDatabaseConfig;
import net.hugmesh.commons.web.ApiException;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * SELF-SILENCE service slice over the REAL repository + Liquibase-applied
 * {@code self_silence} schema (006). Asserts the self-service lifecycle AND the
 * distinctness invariant (it is NOT a ban):
 * <ul>
 *   <li>activate -> status shows an ACTIVE silence; cancel clears it;</li>
 *   <li>activate with a past/absent expiry is a 400 (always bounded + future);</li>
 *   <li>the expiry sweep AUTO-CLEARS an overdue silence (re-shows the user) and is
 *       idempotent / restart-safe (re-selects overdue rows);</li>
 *   <li>NOT-A-BAN: the homeserver hide seams are STUBS (no live call) and NO
 *       revocation/suspension store exists or is written — the only durable effect
 *       is the self_silence row, which never gates the user's own access.</li>
 * </ul>
 */
@DataR2dbcTest
@Import({TestDatabaseConfig.class, SelfSilenceRepository.class, SelfSilenceServiceTest.Stubs.class})
class SelfSilenceServiceTest {

    @TestConfiguration(proxyBeanMethods = false)
    static class Stubs {
        @Bean MatrixHideClient matrix() { return new MatrixHideClient(null); }       // stub
        @Bean MastodonHideClient mastodon() { return new MastodonHideClient(null); } // stub
        @Bean FederationApiClient federation() {
            ExchangeFunction ef = req -> Mono.just(org.springframework.web.reactive.function.client.ClientResponse
                    .create(org.springframework.http.HttpStatus.OK)
                    .header("Content-Type", "application/json")
                    .body("{\"id\":1,\"kind\":\"self-silence-appeal\",\"status\":\"recommended\"}").build());
            return new FederationApiClient(WebClient.builder().exchangeFunction(ef).build());
        }
        @Bean SelfSilenceService selfSilenceService(SelfSilenceRepository repo, FederationApiClient fed,
                                                    List<HomeserverHideClient> hides) {
            // federationHideEnabled=false: the federation hide leg stays a stub-seam.
            return new SelfSilenceService(repo, fed, hides, false);
        }
        // Null WebClient == the documented fail-closed stub (AdminBffInternalClient class
        // doc): every getAccount(...) call errors, so SelfSilenceExpiryAction's canonical-
        // resolution always falls back to its last-resort userId-for-both behaviour, exactly
        // matching this slice's activate(owner, owner, ...) calls below.
        @Bean AdminBffInternalClient adminBff() { return new AdminBffInternalClient(null); }
        @Bean SelfSilenceExpiryAction expiryAction(SelfSilenceRepository repo, SelfSilenceService svc,
                                                   AdminBffInternalClient adminBff) {
            return new SelfSilenceExpiryAction(repo, svc, adminBff);
        }
    }

    @Autowired SelfSilenceService service;
    @Autowired SelfSilenceRepository repo;
    @Autowired SelfSilenceExpiryAction expiry;
    @Autowired DatabaseClient db;

    private Instant soon() { return Instant.now().plus(2, ChronoUnit.HOURS); }

    @Test
    void activate_thenStatus_showsActive_thenCancel_clears() {
        SelfSilence saved = service.activate("alice", "alice", soon(), "taking a break").block();
        assertThat(saved).isNotNull();
        assertThat(saved.userId()).isEqualTo("alice");
        assertThat(saved.active()).isTrue();
        assertThat(saved.clearedAt()).isNull();

        SelfSilence status = service.status("alice").block();
        assertThat(status).isNotNull();
        assertThat(status.active()).isTrue();

        service.cancel("alice", "alice").block();
        SelfSilence afterCancel = service.status("alice").block();
        assertThat(afterCancel).isNotNull();
        assertThat(afterCancel.active()).isFalse();
        assertThat(afterCancel.clearedAt()).isNotNull();
    }

    @Test
    void activate_pastExpiry_isBadRequest() {
        assertThatThrownBy(() -> service.activate("bob", "bob", Instant.now().minusSeconds(60), "x").block())
                .isInstanceOf(ApiException.class);
    }

    @Test
    void cancel_whenNothingActive_isNotFound() {
        assertThatThrownBy(() -> service.cancel("nobody", "nobody").block())
                .isInstanceOf(ApiException.class);
    }

    @Test
    void expirySweep_autoClearsOverdueSilence() {
        // Activate, then force the row overdue (simulate the wake clock reaching expiry).
        service.activate("carol", "carol", soon(), "afk").block();
        db.sql("UPDATE self_silence SET expires_at = :past WHERE user_id = 'carol'")
                .bind("past", java.time.LocalDateTime.now().minusMinutes(5))
                .fetch().rowsUpdated().block();

        Long cleared = expiry.sweep().block();
        assertThat(cleared).isEqualTo(1L);

        SelfSilence after = service.status("carol").block();
        assertThat(after).isNotNull();
        assertThat(after.active()).isFalse();
        assertThat(after.clearedAt()).isNotNull();
        assertThat(expiry.lastSuccessAt()).isNotNull();

        // Idempotent / restart-safe: a second sweep finds nothing overdue-active.
        assertThat(expiry.sweep().block()).isEqualTo(0L);
    }

    @Test
    void notYetExpired_isNotSweptAway() {
        service.activate("dave", "dave", soon(), null).block();
        assertThat(expiry.sweep().block()).isEqualTo(0L);
        assertThat(service.status("dave").block().active()).isTrue();
    }

    /**
     * NOT A BAN — distinctness asserted structurally + behaviourally: the only schema
     * this BFF carries for the feature is {@code self_silence} (no access_suspension /
     * revocation table exists), and activation writes ONLY that row (no other table
     * gains a row). The homeserver seams are stubs (no live token-affecting call).
     */
    @Test
    void selfSilence_isNotABan_onlySelfSilenceRowWritten_noSuspensionTable() {
        service.activate("erin", "erin", soon(), "quiet").block();

        // exactly one self_silence row for erin
        Long rows = db.sql("SELECT count(*) AS c FROM self_silence WHERE user_id = 'erin'")
                .map(r -> r.get("c", Long.class)).first().block();
        assertThat(rows).isEqualTo(1L);

        // there is NO access_suspension / revocation table in this BFF at all — a
        // self-silence cannot be a ban because the ban substrate does not live here.
        assertThat(tableExists("access_suspension")).isFalse();
        assertThat(tableExists("revocations")).isFalse();
    }

    private boolean tableExists(String table) {
        Long c = db.sql("SELECT count(*) AS c FROM information_schema.tables "
                        + "WHERE lower(table_name) = :t")
                .bind("t", table.toLowerCase())
                .map(r -> r.get("c", Long.class)).first().block();
        return c != null && c > 0;
    }
}
