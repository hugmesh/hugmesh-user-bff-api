package net.hugmesh.userbff.auth;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import net.hugmesh.userbff.auth.CasdoorLoginClient.CasdoorLoginResult;

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
        return new CasdoorLoginClient(http, "/api/login", "app-user-bff",
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
        assertThat(uri).contains("clientId=app-user-bff");
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
        CasdoorLoginClient dark = new CasdoorLoginClient(null, "/api/login", "app-user-bff",
                "app-user-bff", "hugmesh", "openid profile email");
        assertThat(dark.enabled()).isFalse();
        assertThatThrownBy(() ->
                dark.login("a", "b", "s", "c", "r", null, null).block())
                .isInstanceOf(IllegalStateException.class);
    }

    // ── "unknown account" is read from Casdoor's wording, in ONE place, as a typed answer ──
    /** Casdoor 3.80.0 controllers/auth.go, English: the refusal for a provider id nobody is linked to. */
    static final String CASDOOR_380_UNKNOWN = "The account for provider: Google and username: a (A) "
            + "does not exist and is not allowed to sign up as new account, please contact your IT support";

    @Test
    void theUnknownAccountRefusalIsTheWordingCasdoor380Uses() {
        assertThat(CasdoorLoginClient.isUnknownAccount(CASDOOR_380_UNKNOWN)).isTrue();
    }

    @Test
    void everyOtherRefusalIsNotAnUnknownAccount() {
        for (String msg : new String[] {
                "invalid username or password", "The user: hugmesh/ann does not exist",
                "the user is forbidden to sign in, please contact the administrator",
                "not allowed to sign up", "does not exist", "", null}) {
            assertThat(CasdoorLoginClient.isUnknownAccount(msg)).as(String.valueOf(msg)).isFalse();
        }
    }

    @Test
    void theResultAnswersTheQuestionSoCallersNeverReadTheText() {
        assertThat(CasdoorLoginResult.error(CASDOOR_380_UNKNOWN).unknownAccount()).isTrue();
        assertThat(CasdoorLoginResult.error("login failed").unknownAccount()).isFalse();
        assertThat(CasdoorLoginResult.code("c").unknownAccount()).isFalse();
        assertThat(CasdoorLoginResult.mfaRequired(java.util.List.of("totp")).unknownAccount()).isFalse();
    }

    @Test
    void aProviderLoginIsTypedUnknownAccountThroughTheWholeParse() {
        CasdoorLoginResult r = clientReturning("{\"status\":\"error\",\"msg\":\""
                + CASDOOR_380_UNKNOWN + "\",\"data\":null}", null)
                .loginWithProvider("provider_google", "pcode", "app-org-x", "chal",
                        "https://app/login/callback", "https://app/bff/oauth/google/callback")
                .block();
        assertThat(r.unknownAccount()).isTrue();
    }

    @Test
    void aProviderLoginAsksCasdoorToAnswerInEnglishSoTheWordingMatches() {
        AtomicReference<ClientRequest> captured = new AtomicReference<>();
        clientReturning("{\"status\":\"ok\",\"data\":\"c\"}", captured)
                .loginWithProvider("provider_google", "pcode", "app-org-x", "chal",
                        "https://app/login/callback", "https://app/bff/oauth/google/callback")
                .block();
        assertThat(captured.get().headers().getFirst("Accept-Language")).isEqualTo("en");
    }
}
