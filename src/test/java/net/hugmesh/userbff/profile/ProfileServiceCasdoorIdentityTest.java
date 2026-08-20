package net.hugmesh.userbff.profile;

import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.client.reactive.MockClientHttpRequest;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import org.springframework.web.reactive.function.client.ExchangeStrategies;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import net.hugmesh.userbff.federation.FederationApiClient;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * REGRESSION test for the "change password doesn't work" defect (operator report
 * 2026-08-19): {@link ProfileService} used to forward the JWT SUBJECT as the Casdoor
 * {@code userName}. The subject is NEVER the Casdoor login name in this platform —
 * it is the Casdoor UUID on a real Casdoor JWT (the gateway's custody swap forwards
 * Casdoor's own token, whose {@code sub} is the user Id) and the composite
 * {@code provider:handle} account id on a bff_-session synthetic principal
 * ({@code BffSessionAuthenticationWebFilter#syntheticJwt}). Casdoor addresses
 * {@code /api/set-password} by {@code <org>/<userName>}, so every live change failed
 * with "The user ... doesn't exist" — and the pre-fix client swallowed that refusal
 * into a success acknowledgement.
 *
 * <p>These tests pin the fixed contract: the USERNAME argument (the token's
 * {@code preferred_username}, threaded by {@link ProfileController#usernameOf}) is
 * what reaches the Casdoor wire — the owner/subject never appears in the form.
 */
class ProfileServiceCasdoorIdentityTest {

    /** Records the outbound Casdoor requests; always answers 200 {"status":"ok"}. */
    static class Recorder implements ExchangeFunction {
        final List<ClientRequest> requests = new ArrayList<>();
        final List<String> bodies = new ArrayList<>();
        @Override public Mono<ClientResponse> exchange(ClientRequest request) {
            requests.add(request);
            MockClientHttpRequest sink = new MockClientHttpRequest(HttpMethod.POST, URI.create("http://casdoor.test"));
            request.writeTo(sink, ExchangeStrategies.withDefaults()).block();
            bodies.add(sink.getBodyAsString().block());
            return Mono.just(ClientResponse.create(HttpStatus.OK)
                    .header("Content-Type", "application/json").body("{\"status\":\"ok\"}").build());
        }
    }

    private static final String SUBJECT_UUID = "9f2d1a34-0000-4bb8-9e11-casdoor-uuid";
    private static final String USERNAME = "alice";

    private final Recorder recorder = new Recorder();

    private ProfileService service() {
        CasdoorUserClient live = new CasdoorUserClient(
                WebClient.builder().exchangeFunction(recorder).build(), "hugmesh");
        return new ProfileService(
                Mockito.mock(UserProfileRepository.class), live,
                Mockito.mock(FederationApiClient.class));
    }

    @Test
    void changePassword_sendsPreferredUsername_neverTheSubject() {
        service().changePassword(SUBJECT_UUID, USERNAME, "old-pw", "new-pw").block();

        assertThat(recorder.requests).hasSize(1);
        assertThat(recorder.requests.get(0).url().getPath()).endsWith("/api/set-password");
        assertThat(recorder.bodies.get(0))
                .contains("userName=" + USERNAME)
                .doesNotContain(SUBJECT_UUID);
    }

    @Test
    void changeEmail_addressesCasdoorByUsername_neverTheSubject() {
        service().changeEmail(SUBJECT_UUID, USERNAME, "new@x.com").block();

        assertThat(recorder.requests).hasSize(1);
        assertThat(recorder.requests.get(0).url().getQuery())
                .contains("id=hugmesh/" + USERNAME);
        assertThat(recorder.requests.get(0).url().getQuery()).doesNotContain(SUBJECT_UUID);
        assertThat(recorder.bodies.get(0))
                .contains("\"name\":\"" + USERNAME + "\"")
                .doesNotContain(SUBJECT_UUID);
    }

    @Test
    void changePassword_bffSyntheticCompositeSubject_neverReachesTheWire() {
        // The OTHER subject shape: a bff_-session synthetic principal's sub is the
        // composite account id ("casdoor:<handle>") — also not a Casdoor login name.
        service().changePassword("casdoor:" + USERNAME, USERNAME, "old-pw", "new-pw").block();

        assertThat(recorder.bodies.get(0))
                .contains("userName=" + USERNAME)
                .doesNotContain("casdoor%3A"); // url-encoded "casdoor:" prefix must not appear
    }
}
