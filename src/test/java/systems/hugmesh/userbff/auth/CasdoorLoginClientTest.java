package systems.hugmesh.userbff.auth;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import systems.hugmesh.userbff.auth.CasdoorLoginClient.CasdoorLoginResult;

import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * {@link CasdoorLoginClient} maps Casdoor's {@code /api/login} {@code Response} envelope onto
 * the three outcomes, and builds the OIDC authorize request (PKCE S256 query params + the
 * {@code type:"code"} JSON body) against the INTERNAL base. Driven by a stub
 * {@link ExchangeFunction} so no live Casdoor is needed.
 */
class CasdoorLoginClientTest {

    private static final String BASE = "http://casdoor:8000";

    private CasdoorLoginClient clientReturning(String json, AtomicReference<ClientRequest> captured) {
        ExchangeFunction fn = req -> {
            if (captured != null) {
                captured.set(req);
            }
            return Mono.just(ClientResponse.create(HttpStatus.OK)
                    .header("Content-Type", MediaType.APPLICATION_JSON_VALUE)
                    .body(json)
                    .build());
        };
        WebClient http = WebClient.builder().baseUrl(BASE).exchangeFunction(fn).build();
        return new CasdoorLoginClient(http, "/api/login", "user-bff",
                "app-user-bff", "hugmesh", "openid profile email");
    }

    @Test
    void okWithCode_yieldsCodeOutcome_andBuildsPkceAuthorizeRequest() {
        AtomicReference<ClientRequest> captured = new AtomicReference<>();
        CasdoorLoginResult result = clientReturning(
                "{\"status\":\"ok\",\"msg\":\"\",\"data\":\"authz-code-123\"}", captured)
                .login("alice", "pw", "state-abc", "challenge-xyz", "https://app/login/callback", null, null)
                .block();

        assertThat(result).isNotNull();
        assertThat(result.kind()).isEqualTo(CasdoorLoginResult.Kind.CODE);
        assertThat(result.code()).isEqualTo("authz-code-123");

        // The authorize request carries the OIDC + PKCE S256 query params against the internal base.
        String uri = captured.get().url().toString();
        assertThat(uri).startsWith(BASE + "/api/login");
        assertThat(uri).contains("clientId=user-bff");
        assertThat(uri).contains("responseType=code");
        assertThat(uri).contains("code_challenge=challenge-xyz");
        assertThat(uri).contains("code_challenge_method=S256");
        assertThat(uri).contains("state=state-abc");
    }

    @Test
    void okWithNextMfa_yieldsMfaRequired_withEnabledTypes() {
        CasdoorLoginResult result = clientReturning(
                "{\"status\":\"ok\",\"data\":\"NextMfa\",\"data2\":[{\"mfaType\":\"totp\"},{\"mfaType\":\"sms\"}]}", null)
                .login("alice", "pw", "s", "c", "https://app/login/callback", null, null)
                .block();

        assertThat(result).isNotNull();
        assertThat(result.kind()).isEqualTo(CasdoorLoginResult.Kind.MFA_REQUIRED);
        assertThat(result.mfaTypes()).containsExactly("totp", "sms");
    }

    @Test
    void statusError_yieldsErrorOutcome_withCasdoorMessage() {
        CasdoorLoginResult result = clientReturning(
                "{\"status\":\"error\",\"msg\":\"password is incorrect\"}", null)
                .login("alice", "bad", "s", "c", "https://app/login/callback", null, null)
                .block();

        assertThat(result).isNotNull();
        assertThat(result.kind()).isEqualTo(CasdoorLoginResult.Kind.ERROR);
        assertThat(result.message()).isEqualTo("password is incorrect");
    }

    @Test
    void darkClient_failsClosed() {
        CasdoorLoginClient dark = new CasdoorLoginClient(null, "/api/login", "user-bff",
                "app-user-bff", "hugmesh", "openid profile email");
        assertThat(dark.enabled()).isFalse();
        assertThatThrownBy(() ->
                dark.login("a", "b", "s", "c", "r", null, null).block())
                .isInstanceOf(IllegalStateException.class);
    }
}
