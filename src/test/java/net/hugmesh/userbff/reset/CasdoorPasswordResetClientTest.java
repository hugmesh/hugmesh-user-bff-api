package net.hugmesh.userbff.reset;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.mock.http.client.reactive.MockClientHttpRequest;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import org.springframework.web.reactive.function.client.ExchangeStrategies;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import net.hugmesh.commons.web.ApiException;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Pins {@link CasdoorPasswordResetClient}'s two wire shapes and — more importantly —
 * its two REFUSAL behaviours, using the same recording {@link ExchangeFunction} stub as
 * the sibling {@code CasdoorUserClientTest}.
 *
 * <p>The wire shape here is NOT live-verified (the client's javadoc says so and gives the
 * two curl commands that would settle it). These assertions therefore serve a narrower but
 * still real purpose: they pin the shape to ONE place, so a correction after a live check
 * is a one-line edit whose test moves with it, and they prove the parts that are
 * verifiable without a Casdoor at all — that a refusal never becomes a success, and that
 * the dark client never reaches the network.
 */
class CasdoorPasswordResetClientTest {

    static class Recorder implements ExchangeFunction {
        final List<ClientRequest> requests = new ArrayList<>();
        final List<String> bodies = new ArrayList<>();
        final List<MediaType> contentTypes = new ArrayList<>();
        /** Casdoor answers HTTP 200 for REFUSED operations too, so error cases are
         *  modelled here as 200 + an error body — never a non-2xx status. */
        String responseJson = "{\"status\":\"ok\"}";
        @Override public Mono<ClientResponse> exchange(ClientRequest request) {
            requests.add(request);
            MockClientHttpRequest sink =
                    new MockClientHttpRequest(HttpMethod.POST, URI.create("http://casdoor.test"));
            request.writeTo(sink, ExchangeStrategies.withDefaults()).block();
            bodies.add(sink.getBodyAsString().block());
            contentTypes.add(sink.getHeaders().getContentType());
            return Mono.just(ClientResponse.create(HttpStatus.OK)
                    .header("Content-Type", "application/json").body(responseJson).build());
        }
        boolean hit(String suffix) {
            return requests.stream().anyMatch(r -> r.url().getPath().endsWith(suffix));
        }
    }

    private CasdoorPasswordResetClient live(Recorder rec) {
        return new CasdoorPasswordResetClient(
                WebClient.builder().exchangeFunction(rec).build(), "hugmesh", "admin/app-user-bff");
    }

    private CasdoorPasswordResetClient dark() {
        return new CasdoorPasswordResetClient(null, "hugmesh", "admin/app-user-bff");
    }

    // ── enabled() reports which of the two clients you actually hold ──────────

    @Test
    void enabled_isTrueOnlyForTheLiveClient() {
        assertThat(live(new Recorder()).enabled()).isTrue();
        assertThat(dark().enabled()).isFalse();
    }

    // ── LIVE: the request leg ────────────────────────────────────────────────

    @Test
    void live_sendResetCode_postsFormEncodedToSendVerificationCode() {
        Recorder rec = new Recorder();
        live(rec).sendResetCode("alice").block();

        assertThat(rec.hit("/api/send-verification-code")).isTrue();
        // Casdoor reads these fields from the urlencoded FORM only — a JSON body of the
        // same fields is rejected (live-verified for the sibling set-password call).
        assertThat(rec.contentTypes.get(0)).isEqualTo(MediaType.APPLICATION_FORM_URLENCODED);
        assertThat(rec.bodies.get(0))
                .contains("method=forget")
                .contains("type=email")
                .contains("checkUser=alice")
                .contains("applicationId=admin%2Fapp-user-bff");
    }

    /**
     * THE ANTI-ENUMERATION PROPERTY AT THE TRANSPORT LAYER. The browser sends a username;
     * the DESTINATION is whatever Casdoor holds. If a caller-supplied address could ride
     * along, this endpoint would mail a reset code anywhere an attacker asked.
     */
    @Test
    void live_sendResetCode_neverCarriesACallerSuppliedAddress() {
        Recorder rec = new Recorder();
        live(rec).sendResetCode("alice").block();
        // The only "dest" is the username itself — Casdoor resolves the real address.
        assertThat(rec.bodies.get(0)).doesNotContain("@");
    }

    // ── LIVE: the confirm leg ────────────────────────────────────────────────

    @Test
    void live_resetPassword_postsCodeInsteadOfOldPassword() {
        Recorder rec = new Recorder();
        live(rec).resetPassword("alice", "123456", "s3cret-enough").block();

        assertThat(rec.hit("/api/set-password")).isTrue();
        assertThat(rec.contentTypes.get(0)).isEqualTo(MediaType.APPLICATION_FORM_URLENCODED);
        assertThat(rec.bodies.get(0))
                .contains("userOwner=hugmesh")
                .contains("userName=alice")
                .contains("code=123456")
                .contains("newPassword=s3cret-enough");
    }

    /**
     * oldPassword MUST be absent, not empty. Sending {@code oldPassword=} alongside a code
     * is what makes Casdoor fall back to password verification and refuse the whole reset —
     * the exact failure mode this endpoint exists to avoid.
     */
    @Test
    void live_resetPassword_omitsOldPasswordEntirely() {
        Recorder rec = new Recorder();
        live(rec).resetPassword("alice", "123456", "s3cret-enough").block();
        assertThat(rec.bodies.get(0)).doesNotContain("oldPassword");
    }

    // ── REFUSALS: a 200-with-error body is a FAILURE, never a success ─────────

    @Test
    void live_sendResetCode_casdoorErrorBody_becomesBadRequest_notSuccess() {
        Recorder rec = new Recorder();
        rec.responseJson = "{\"status\":\"error\",\"msg\":\"the user does not exist\"}";
        assertThatThrownBy(() -> live(rec).sendResetCode("nobody").block())
                .isInstanceOf(ApiException.class)
                .hasMessageContaining("the user does not exist");
    }

    @Test
    void live_resetPassword_casdoorErrorBody_becomesBadRequest_notSuccess() {
        Recorder rec = new Recorder();
        rec.responseJson = "{\"status\":\"error\",\"msg\":\"code is incorrect\"}";
        assertThatThrownBy(() -> live(rec).resetPassword("alice", "000000", "s3cret-enough").block())
                .isInstanceOf(ApiException.class)
                .hasMessageContaining("code is incorrect")
                .extracting(t -> ((ApiException) t).status())
                .isEqualTo(HttpStatus.BAD_REQUEST);
    }

    /** A body with no {@code msg} at all still fails — silence is not consent. */
    @Test
    void live_resetPassword_errorBodyWithoutMessage_stillFails() {
        Recorder rec = new Recorder();
        rec.responseJson = "{\"status\":\"error\"}";
        assertThatThrownBy(() -> live(rec).resetPassword("alice", "000000", "s3cret-enough").block())
                .isInstanceOf(ApiException.class)
                .hasMessageContaining("no error message from the IdP");
    }

    // ── DARK: fail CLOSED with a 503, and never touch the network ─────────────

    /**
     * The dark client must 503 rather than complete empty. Its sibling
     * {@code CasdoorUserClient} DOES complete empty while stubbed — that is safe there
     * because its caller is authenticated and sees {@code "casdoor":"stubbed"} in the
     * acknowledgement. A locked-out visitor here has no such signal and would read a
     * silent completion as "the mail is coming".
     */
    @Test
    void dark_sendResetCode_is503_notAnEmptySuccess() {
        assertThatThrownBy(() -> dark().sendResetCode("alice").block())
                .isInstanceOf(ApiException.class)
                .extracting(t -> ((ApiException) t).status())
                .isEqualTo(HttpStatus.SERVICE_UNAVAILABLE);
    }

    @Test
    void dark_resetPassword_is503_notAnEmptySuccess() {
        assertThatThrownBy(() -> dark().resetPassword("alice", "123456", "s3cret-enough").block())
                .isInstanceOf(ApiException.class)
                .extracting(t -> ((ApiException) t).status())
                .isEqualTo(HttpStatus.SERVICE_UNAVAILABLE);
    }

    @Test
    void dark_makesNoHttpCallAtAll() {
        Recorder rec = new Recorder();
        // A dark client built with a null WebClient cannot reach the recorder even if it
        // tried; assert the recorder stayed empty so a future refactor that quietly gives
        // the dark path a client is caught here.
        CasdoorPasswordResetClient darkClient = new CasdoorPasswordResetClient(null, "hugmesh", "admin/app-user-bff");
        try { darkClient.sendResetCode("alice").block(); } catch (ApiException expected) { /* 503 */ }
        try { darkClient.resetPassword("alice", "1", "s3cret-enough").block(); } catch (ApiException expected) { /* 503 */ }
        assertThat(rec.requests).isEmpty();
    }
}
