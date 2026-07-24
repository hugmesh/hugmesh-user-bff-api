package systems.hugmesh.userbff.profile;

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

import java.net.URI;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies the {@link CasdoorUserClient}: in LIVE mode it issues the CONFIRMED
 * set-password / update-user(email) calls (recording {@link ExchangeFunction}
 * stub); in STUB mode (null WebClient) it makes no HTTP call but the reactive flow
 * still completes.
 *
 * <p>The wire shape pinned here was LIVE-VERIFIED (2026-07) against the compose
 * stack's Casdoor with a throwaway user:
 * <ul>
 *   <li>set-password accepts ONLY an urlencoded form (a JSON body of the same
 *       fields fails with "The user: / doesn't exist"), and verifies oldPassword
 *       even for admin-credential callers;</li>
 *   <li>update-user with the partial {@code {owner,name,email}} body REQUIRES
 *       {@code columns=email} (without it: "Display name cannot be empty"); with
 *       it the email is written and all other fields are preserved.</li>
 * </ul>
 * These assertions pin exactly that confirmed contract so a regression back to
 * JSON-encoding or a dropped columns param fails CI.
 */
class CasdoorUserClientTest {

    static class Recorder implements ExchangeFunction {
        final List<ClientRequest> requests = new ArrayList<>();
        final List<String> bodies = new ArrayList<>();
        final List<MediaType> contentTypes = new ArrayList<>();
        @Override public Mono<ClientResponse> exchange(ClientRequest request) {
            requests.add(request);
            MockClientHttpRequest sink = new MockClientHttpRequest(HttpMethod.POST, URI.create("http://casdoor.test"));
            request.writeTo(sink, ExchangeStrategies.withDefaults()).block();
            bodies.add(sink.getBodyAsString().block());
            contentTypes.add(sink.getHeaders().getContentType());
            return Mono.just(ClientResponse.create(HttpStatus.OK)
                    .header("Content-Type", "application/json").body("{\"status\":\"ok\"}").build());
        }
        boolean hit(String suffix) { return requests.stream().anyMatch(r -> r.url().getPath().endsWith(suffix)); }
    }

    private CasdoorUserClient live(Recorder rec) {
        return new CasdoorUserClient(WebClient.builder().exchangeFunction(rec).build(), "hugmesh");
    }

    @Test
    void live_changePassword_callsSetPassword() {
        Recorder rec = new Recorder();
        live(rec).changePassword("alice", "old", "new").block();
        assertThat(rec.hit("/api/set-password")).isTrue();
    }

    @Test
    void live_changePassword_sendsUrlencodedForm_notJson() {
        // LIVE-CONFIRMED: Casdoor set-password reads ONLY the urlencoded form; a JSON
        // body of the same fields is rejected. Pin the encoding + all four fields.
        Recorder rec = new Recorder();
        live(rec).changePassword("alice", "old-pw", "new-pw").block();
        assertThat(rec.contentTypes.get(0)).isEqualTo(MediaType.APPLICATION_FORM_URLENCODED);
        assertThat(rec.bodies.get(0))
                .contains("userOwner=hugmesh")
                .contains("userName=alice")
                .contains("oldPassword=old-pw")
                .contains("newPassword=new-pw");
    }

    @Test
    void live_changeEmail_callsUpdateUser() {
        Recorder rec = new Recorder();
        live(rec).changeEmail("alice", "new@x.com").block();
        assertThat(rec.hit("/api/update-user")).isTrue();
        assertThat(rec.requests.get(0).url().getQuery()).contains("id=hugmesh/alice");
    }

    @Test
    void live_changeEmail_scopesWriteWithColumnsEmail() {
        // LIVE-CONFIRMED: without columns=email Casdoor full-object-validates the
        // partial body and rejects it ("Display name cannot be empty"); with it the
        // write touches ONLY the email column. Pin the param + the JSON partial body.
        Recorder rec = new Recorder();
        live(rec).changeEmail("alice", "new@x.com").block();
        assertThat(rec.requests.get(0).url().getQuery()).contains("columns=email");
        assertThat(rec.contentTypes.get(0)).isEqualTo(MediaType.APPLICATION_JSON);
        assertThat(rec.bodies.get(0))
                .contains("\"owner\":\"hugmesh\"")
                .contains("\"name\":\"alice\"")
                .contains("\"email\":\"new@x.com\"");
    }

    @Test
    void stub_noHttpButCompletes() {
        CasdoorUserClient stub = new CasdoorUserClient(null, "hugmesh");
        assertThat(stub.enabled()).isFalse();
        // completes empty without throwing
        stub.changePassword("alice", "old", "new").block();
        stub.changeEmail("alice", "new@x.com").block();
    }
}
