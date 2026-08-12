package net.hugmesh.userbff.hsproxy;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Guards the Boot-4 JSON decode path of the homeserver token broker.
 *
 * <p>Before the Boot-4 fix the broker decoded responses with
 * {@code bodyToMono(com.fasterxml.jackson.databind.JsonNode.class)} — a Jackson-2
 * type the Boot-4 reactive WebFlux codec (Jackson 3 / tools.jackson) cannot
 * decode, throwing a {@code CodecException} so EVERY Matrix/Mastodon token mint
 * failed at runtime. It was silent because no test exercised the broker's real
 * HTTP decode.
 *
 * <p>These tests stub the homeserver exchange and drive the public
 * {@code mintMatrix}/{@code mintMastodon} flows end-to-end through the real codec,
 * so a regression to a codec-incompatible decode fails fast here.
 */
class ServiceTokenBrokerTest {

    /** An exchange that answers every request with the given JSON body (200). */
    private static ExchangeFunction jsonStub(String body) {
        return request -> Mono.just(ClientResponse.create(HttpStatus.OK)
                .header("Content-Type", MediaType.APPLICATION_JSON_VALUE)
                .body(body)
                .build());
    }

    private static ServiceTokenBroker brokerFor(String responseBody) {
        WebClient hs = WebClient.builder()
                .exchangeFunction(jsonStub(responseBody))
                .build();
        HsTokenCustody custody = mock(HsTokenCustody.class);
        when(custody.upsert(any(), any(), any(), any(), any(), any()))
                .thenReturn(Mono.empty());
        HsTokenRevocationHashWriter hashWriter =
                mock(HsTokenRevocationHashWriter.class);
        when(hashWriter.recordBrokered(any(), any(), any()))
                .thenReturn(Mono.empty());
        return new ServiceTokenBroker(hs, hs, "svc-pw", custody, hashWriter);
    }

    /** Broker with the given service password (and a stub HS that would 200 if reached). */
    private static ServiceTokenBroker brokerWithPassword(String svcPassword) {
        WebClient hs = WebClient.builder()
                .exchangeFunction(jsonStub("{\"access_token\":\"should-not-be-reached\"}"))
                .build();
        return new ServiceTokenBroker(hs, hs, svcPassword,
                mock(HsTokenCustody.class), mock(HsTokenRevocationHashWriter.class));
    }

    @Test
    void mintMatrix_decodesSynapseJson_throughTheBoot4Jackson3Codec() {
        // Synapse /register returns an access_token directly (one-shot success).
        ServiceTokenBroker broker = brokerFor(
                "{\"access_token\":\"syt_abc\",\"user_id\":\"@bob:hs\"}");

        StepVerifier.create(broker.mintMatrix("sub-1", "bob"))
                .assertNext(token ->
                        assertThat(token.accessToken()).isEqualTo("syt_abc"))
                .verifyComplete();
    }

    // ── Mastodon mint = the REAL OAuth contract (app creds + grant/register) ─────
    // The old bare {grant_type,username,password} body (mock-bff port) never worked
    // against any real doorkeeper (401 invalid_client). These drive the full flow
    // with a PATH-ROUTED stub: /api/v1/apps → creds; /oauth/token consumed in call
    // order (password grant first, client_credentials second); /api/v1/accounts.

    private static final String APP_CREDS =
            "{\"client_id\":\"cid-1\",\"client_secret\":\"csec-1\"}";

    /** Routes by request path; each path's responses are consumed IN ORDER (last repeats). */
    private static ExchangeFunction routedStub(java.util.Map<String, java.util.List<ClientResponse>> routes,
                                               java.util.Map<String, java.util.concurrent.atomic.AtomicInteger> hits) {
        return request -> {
            String path = request.url().getPath();
            java.util.List<ClientResponse> rs = routes.get(path);
            if (rs == null) {
                return Mono.just(ClientResponse.create(HttpStatus.NOT_FOUND)
                        .header("Content-Type", MediaType.APPLICATION_JSON_VALUE)
                        .body("{\"error\":\"unrouted path " + path + "\"}").build());
            }
            int n = hits.computeIfAbsent(path, k -> new java.util.concurrent.atomic.AtomicInteger())
                    .getAndIncrement();
            return Mono.just(rs.get(Math.min(n, rs.size() - 1)));
        };
    }

    private static ClientResponse json(HttpStatus status, String body) {
        return ClientResponse.create(status)
                .header("Content-Type", MediaType.APPLICATION_JSON_VALUE)
                .body(body).build();
    }

    private static ServiceTokenBroker mastodonBroker(java.util.Map<String, java.util.List<ClientResponse>> routes,
                                                     java.util.Map<String, java.util.concurrent.atomic.AtomicInteger> hits) {
        WebClient hs = WebClient.builder().exchangeFunction(routedStub(routes, hits)).build();
        HsTokenCustody custody = mock(HsTokenCustody.class);
        when(custody.upsert(any(), any(), any(), any(), any(), any())).thenReturn(Mono.empty());
        HsTokenRevocationHashWriter hashWriter = mock(HsTokenRevocationHashWriter.class);
        when(hashWriter.recordBrokered(any(), any(), any())).thenReturn(Mono.empty());
        return new ServiceTokenBroker(hs, hs, "svc-pw", "e2e.local", custody, hashWriter);
    }

    @Test
    void mintMastodon_recoversViaPasswordGrant_withAppCreds() {
        var hits = new java.util.HashMap<String, java.util.concurrent.atomic.AtomicInteger>();
        ServiceTokenBroker broker = mastodonBroker(java.util.Map.of(
                "/api/v1/apps", java.util.List.of(json(HttpStatus.OK, APP_CREDS)),
                "/oauth/token", java.util.List.of(json(HttpStatus.OK,
                        "{\"access_token\":\"mst_xyz\",\"token_type\":\"Bearer\"}"))), hits);

        StepVerifier.create(broker.mintMastodon("sub-1", "bob"))
                .assertNext(token -> assertThat(token.accessToken()).isEqualTo("mst_xyz"))
                .verifyComplete();
        assertThat(hits.get("/api/v1/apps").get()).isEqualTo(1);
        assertThat(hits.get("/oauth/token").get()).isEqualTo(1); // password grant only
    }

    @Test
    void mintMastodon_registersWhenGrantRefused_userTokenReturnedDirectly() {
        var hits = new java.util.HashMap<String, java.util.concurrent.atomic.AtomicInteger>();
        ServiceTokenBroker broker = mastodonBroker(java.util.Map.of(
                "/api/v1/apps", java.util.List.of(json(HttpStatus.OK, APP_CREDS)),
                "/oauth/token", java.util.List.of(
                        json(HttpStatus.BAD_REQUEST, "{\"error\":\"invalid_grant\"}"),   // password grant
                        json(HttpStatus.OK, "{\"access_token\":\"app-tok\"}")),          // client_credentials
                "/api/v1/accounts", java.util.List.of(json(HttpStatus.OK,
                        "{\"access_token\":\"mst_new\",\"token_type\":\"Bearer\"}"))), hits);

        StepVerifier.create(broker.mintMastodon("sub-1", "bob"))
                .assertNext(token -> assertThat(token.accessToken()).isEqualTo("mst_new"))
                .verifyComplete();
        assertThat(hits.get("/oauth/token").get()).isEqualTo(2);
        assertThat(hits.get("/api/v1/accounts").get()).isEqualTo(1);
    }

    @Test
    void mintMastodon_appCredsCachedAcrossMints() {
        var hits = new java.util.HashMap<String, java.util.concurrent.atomic.AtomicInteger>();
        ServiceTokenBroker broker = mastodonBroker(java.util.Map.of(
                "/api/v1/apps", java.util.List.of(json(HttpStatus.OK, APP_CREDS)),
                "/oauth/token", java.util.List.of(json(HttpStatus.OK,
                        "{\"access_token\":\"mst_xyz\"}"))), hits);

        StepVerifier.create(broker.mintMastodon("sub-1", "bob")).expectNextCount(1).verifyComplete();
        StepVerifier.create(broker.mintMastodon("sub-1", "bob")).expectNextCount(1).verifyComplete();
        assertThat(hits.get("/api/v1/apps").get()).isEqualTo(1); // registered once, cached
    }

    @Test
    void mintMastodon_localpartFoldedToMastodonCharset() {
        // 'Bea59B50-15a1.x' → mastodon charset [a-z0-9_]: fold '-'/'.' to '_'.
        assertThat(ServiceTokenBroker.mastodonLocalpart("Bea59B50-15a1.x@e2e.local"))
                .isEqualTo("bea59b50_15a1_x");
        assertThat(ServiceTokenBroker.mastodonLocalpart("---")).isEqualTo("user");
        // A full casdoor-UUID handle (36 chars folded) truncates to Mastodon's 30-char cap.
        assertThat(ServiceTokenBroker.mastodonLocalpart("bea59b50-15a1-4efc-82de-87d3fe9b2322"))
                .isEqualTo("bea59b50_15a1_4efc_82de_87d3fe")
                .hasSize(30);
        var hits = new java.util.HashMap<String, java.util.concurrent.atomic.AtomicInteger>();
        ServiceTokenBroker broker = mastodonBroker(java.util.Map.of(
                "/api/v1/apps", java.util.List.of(json(HttpStatus.OK, APP_CREDS)),
                "/oauth/token", java.util.List.of(json(HttpStatus.OK,
                        "{\"access_token\":\"mst_xyz\"}"))), hits);
        StepVerifier.create(broker.mintMastodon("sub-1", "Bea59B50-15a1.x"))
                .assertNext(t -> assertThat(t.localpart()).isEqualTo("bea59b50_15a1_x"))
                .verifyComplete();
    }

    @Test
    void mintMastodon_failsClosed503_whenEmailDomainUnset() {
        WebClient hs = WebClient.builder()
                .exchangeFunction(jsonStub("{\"access_token\":\"should-not-be-reached\"}"))
                .build();
        ServiceTokenBroker broker = new ServiceTokenBroker(hs, hs, "svc-pw", "",
                mock(HsTokenCustody.class), mock(HsTokenRevocationHashWriter.class));

        StepVerifier.create(broker.mintMastodon("sub-1", "bob"))
                .expectErrorSatisfies(e -> assertThat(e)
                        .isInstanceOf(ResponseStatusException.class)
                        .extracting(ex -> ((ResponseStatusException) ex).getStatusCode().value())
                        .isEqualTo(503))
                .verify();
    }

    // --- 4xx bodies are PROTOCOL, not errors (Synapse UIA / register→login fallback) ----
    // retrieve() threw on any 4xx, so the UIA leg (Synapse returns the stage-2 `session`
    // in a 401) could never complete and the register→login fallback never ran — the
    // Matrix mint was dead against any real UIA-flow Synapse. These pin the exchange-
    // based decode: 401/403 bodies flow through the protocol handling; 5xx stays an error.

    /** An exchange that answers request N with statuses[N]/bodies[N] (last repeats). */
    private static ExchangeFunction sequenceStub(java.util.concurrent.atomic.AtomicInteger calls,
                                                 HttpStatus[] statuses, String[] bodies) {
        return request -> {
            int n = Math.min(calls.getAndIncrement(), bodies.length - 1);
            return Mono.just(ClientResponse.create(statuses[n])
                    .header("Content-Type", MediaType.APPLICATION_JSON_VALUE)
                    .body(bodies[n])
                    .build());
        };
    }

    private static ServiceTokenBroker brokerForSequence(java.util.concurrent.atomic.AtomicInteger calls,
                                                        HttpStatus[] statuses, String[] bodies) {
        WebClient hs = WebClient.builder()
                .exchangeFunction(sequenceStub(calls, statuses, bodies))
                .build();
        HsTokenCustody custody = mock(HsTokenCustody.class);
        when(custody.upsert(any(), any(), any(), any(), any(), any()))
                .thenReturn(Mono.empty());
        HsTokenRevocationHashWriter hashWriter = mock(HsTokenRevocationHashWriter.class);
        when(hashWriter.recordBrokered(any(), any(), any()))
                .thenReturn(Mono.empty());
        return new ServiceTokenBroker(hs, hs, "svc-pw", custody, hashWriter);
    }

    @Test
    void mintMatrix_completesUiaRegister_throughThe401SessionBody() {
        // Real Synapse UIA shape: stage-1 register → 401 {"session","flows"}; the broker
        // must PARSE that 401 (not throw) and drive stage-2 m.login.dummy → token.
        var calls = new java.util.concurrent.atomic.AtomicInteger();
        ServiceTokenBroker broker = brokerForSequence(calls,
                new HttpStatus[]{HttpStatus.UNAUTHORIZED, HttpStatus.OK},
                new String[]{
                        "{\"session\":\"sess-1\",\"flows\":[{\"stages\":[\"m.login.dummy\"]}],\"params\":{}}",
                        "{\"access_token\":\"syt_uia\",\"user_id\":\"@bob:hs\"}"});

        StepVerifier.create(broker.mintMatrix("sub-1", "bob"))
                .assertNext(token -> assertThat(token.accessToken()).isEqualTo("syt_uia"))
                .verifyComplete();
        assertThat(calls.get()).isEqualTo(2); // stage-1 + stage-2, no login needed
    }

    @Test
    void mintMatrix_fallsBackToLogin_whenRegistrationRefused() {
        // Registration disabled (or localpart taken): the 4xx register body has no
        // session/access_token → the broker falls through to password login.
        var calls = new java.util.concurrent.atomic.AtomicInteger();
        ServiceTokenBroker broker = brokerForSequence(calls,
                new HttpStatus[]{HttpStatus.FORBIDDEN, HttpStatus.OK},
                new String[]{
                        "{\"errcode\":\"M_FORBIDDEN\",\"error\":\"Registration has been disabled\"}",
                        "{\"access_token\":\"syt_login\",\"user_id\":\"@bob:hs\"}"});

        StepVerifier.create(broker.mintMatrix("sub-1", "bob"))
                .assertNext(token -> assertThat(token.accessToken()).isEqualTo("syt_login"))
                .verifyComplete();
        assertThat(calls.get()).isEqualTo(2); // refused register + successful login
    }

    @Test
    void mintMatrix_homeserver5xx_staysAnError() {
        var calls = new java.util.concurrent.atomic.AtomicInteger();
        ServiceTokenBroker broker = brokerForSequence(calls,
                new HttpStatus[]{HttpStatus.INTERNAL_SERVER_ERROR},
                new String[]{"{\"error\":\"boom\"}"});

        StepVerifier.create(broker.mintMatrix("sub-1", "bob"))
                .expectError()
                .verify();
    }

    @Test
    void mintMastodon_bothLegsRefused_failsClosed_noTokenMinted() {
        // Grant refused AND registration refused (e.g. the localpart is taken by an
        // account this broker does not own — a tootctl-seeded user with a random
        // password): 4xx bodies are parsed (not thrown) but carry no access_token →
        // the explicit fail-closed error, never a custody row, never a takeover.
        var hits = new java.util.HashMap<String, java.util.concurrent.atomic.AtomicInteger>();
        ServiceTokenBroker broker = mastodonBroker(java.util.Map.of(
                "/api/v1/apps", java.util.List.of(json(HttpStatus.OK, APP_CREDS)),
                "/oauth/token", java.util.List.of(
                        json(HttpStatus.BAD_REQUEST, "{\"error\":\"invalid_grant\"}"),
                        json(HttpStatus.OK, "{\"access_token\":\"app-tok\"}")),
                "/api/v1/accounts", java.util.List.of(json(HttpStatus.UNPROCESSABLE_ENTITY,
                        "{\"error\":\"Validation failed: Username has already been taken\"}"))), hits);

        StepVerifier.create(broker.mintMastodon("sub-1", "bob"))
                .expectErrorSatisfies(e ->
                        assertThat(e).hasMessageContaining("no access_token"))
                .verify();
    }

    // --- Fail-closed when the service password is unprovisioned (empty default) ---------
    // app.hs-token.svc-password now carries an EMPTY default so an unset secret boots the
    // context cleanly instead of crashing on an unresolved placeholder; a mint must then
    // 503 BEFORE touching the homeserver (mirrors an unconfigured custody key → 503).

    @Test
    void mintMatrix_failsClosed503_whenServicePasswordUnset() {
        ServiceTokenBroker broker = brokerWithPassword("");

        StepVerifier.create(broker.mintMatrix("sub-1", "bob"))
                .expectErrorSatisfies(e -> assertThat(e)
                        .isInstanceOf(ResponseStatusException.class)
                        .extracting(ex -> ((ResponseStatusException) ex).getStatusCode().value())
                        .isEqualTo(503))
                .verify();
    }

    @Test
    void mintMastodon_failsClosed503_whenServicePasswordBlank() {
        ServiceTokenBroker broker = brokerWithPassword("   ");

        StepVerifier.create(broker.mintMastodon("sub-1", "bob"))
                .expectErrorSatisfies(e -> assertThat(e)
                        .isInstanceOf(ResponseStatusException.class)
                        .extracting(ex -> ((ResponseStatusException) ex).getStatusCode().value())
                        .isEqualTo(503))
                .verify();
    }
}
