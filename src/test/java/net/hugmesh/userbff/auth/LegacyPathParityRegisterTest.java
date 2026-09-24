package net.hugmesh.userbff.auth;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InOrder;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webflux.test.autoconfigure.WebFluxTest;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseCookie;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.core.publisher.Mono;
import net.hugmesh.authcore.config.SessionCookieService;
import net.hugmesh.userbff.config.BffSessionAuthenticationWebFilter;
import net.hugmesh.userbff.config.SecurityConfig;
import net.hugmesh.userbff.hsproxy.HsTokenCustody;
import net.hugmesh.userbff.hsproxy.ServiceTokenBroker;
import net.hugmesh.userbff.web.ApiExceptionHandler;

import java.time.Duration;
import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * Status-code + body parity pins for {@link LegacyPathParityController}'s two REGISTER legs —
 * {@code POST /bff/register/google} and {@code POST /bff/register/discord} — against
 * hugmesh-admin-bff-api's {@code AuthController#registerGoogle}/{@code registerDiscord}
 * (operator decision 25 on hugmesh-generator#347, and decision 40, which aligned the compose
 * route table onto user-bff and so made both paths 404 on BOTH lanes until these handlers
 * existed).
 *
 * <p><b>These are PRE-AUTH paths</b>, so unlike the three legs pinned in
 * {@link LegacyPathParityControllerTest} there is no principal: every request here is
 * ANONYMOUS and travels the REAL {@link SecurityConfig} prod chain, which makes each 200/403/409
 * below simultaneously a pin that the two exact {@code permitAll} entries are in place. A
 * missing {@code permitAll} would surface as a 401 and fail every test in this class.
 * {@link net.hugmesh.userbff.config.SecurityConfigSsoPathRulesTest} pins the negative half (a
 * sibling under {@code /bff/register/**} is NOT permitted).
 *
 * <p><b>The two operator rulings are pinned here, not merely documented</b> (hugmesh-generator#347,
 * 2026-09-18):
 * <ul>
 *   <li><b>Decision 57 = 409.</b> {@code alreadyCompleteAccount_is409_andNeverMintsASession}
 *       (both legs). admin-bff calls {@code AccountStore.restartOnboarding} at that exact
 *       point; this class answers a {@code 409 Conflict} with the existing, already-onboarded
 *       account instead — no restart, no session, no usage row. The body is asserted, not just
 *       the status, because the localpart-collision leg is ALSO a 409.</li>
 *   <li><b>Decision 55 = yes.</b> A performed registration is recorded on admin-bff's usage
 *       table through {@code AdminBffInternalClient#recordUsage} with admin-bff's own triple —
 *       bare handle, the account's verbatim roles, {@code "register"} — fired BEFORE the mint
 *       and detached from it, so a usage failure never fails the caller. The wire shape and the
 *       end-to-end detachment against a stub admin-bff are pinned in
 *       {@link LegacyPathParityRegisterUsageWireTest}; the mock-level pins here cover the
 *       arguments, the ordering and every path that must NOT record.</li>
 * </ul>
 */
@WebFluxTest(controllers = LegacyPathParityController.class)
@Import({SecurityConfig.class, CanonicalIdentityResolver.class, ApiExceptionHandler.class})
class LegacyPathParityRegisterTest {

    private static final String EMAIL = "alice@example.test";
    private static final String GOOGLE_ID = "google:" + EMAIL;
    private static final String DISCORD_HANDLE = "dragoneer";
    private static final String DISCORD_ID = "discord:" + DISCORD_HANDLE;
    private static final String TOKEN = "bff_freshly-minted-session";

    @Autowired ApplicationContext context;
    WebTestClient client;

    @MockitoBean ReactiveJwtDecoder jwtDecoder;
    @MockitoBean AdminBffInternalClient adminBff;
    @MockitoBean HsTokenCustody custody;
    @MockitoBean ServiceTokenBroker broker;
    @MockitoBean SessionCookieService cookies;

    @BeforeEach
    void setUp() {
        client = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
        // Cookie mode OFF is the SHIPPED default (app.session.cookie.enabled=false), so it is
        // the default posture here; cookieMode_mintsTheBffCookie below flips it explicitly.
        when(cookies.enabled()).thenReturn(false);
        // The decision-55 usage leg is fire-and-forget: the controller subscribes to whatever
        // Mono the client hands back, so an UNSTUBBED mock (null) would NPE inside the chain
        // and turn every happy path below into a 500. Stub it green by default; the usage
        // tests further down override it per case.
        when(adminBff.recordUsage(anyString(), anyList(), anyString())).thenReturn(Mono.empty());
    }

    /** An account view as admin-bff's internal {@code AccountOut} deserialises after
     *  {@code POST /bff/internal/accounts/ensure} — which has ALREADY resolved and persisted
     *  the collision-checked localpart ({@code withLocalpart}). */
    private static AdminBffInternalClient.AccountView account(String id, String provider,
                                                              String handle, boolean complete) {
        return new AdminBffInternalClient.AccountView(id, provider, handle, complete,
                List.of("user", "matrix", "mastodon"), handle.replaceAll("[^a-z0-9]", ""), "");
    }

    private WebTestClient.ResponseSpec postGoogle(String bodyJson) {
        return client.post().uri("/bff/register/google")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(bodyJson).exchange();
    }

    private WebTestClient.ResponseSpec postDiscord(String bodyJson) {
        return client.post().uri("/bff/register/discord")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(bodyJson).exchange();
    }

    // ── The happy path: invited ⇒ account ensured ⇒ session minted ─────────────────────────

    /**
     * admin-bff's {@code registerGoogle}: {@code isEmailInvited} ⇒ {@code ensureAccount("google",
     * email)} ⇒ (restartOnboarding, a NO-OP for a fresh row) ⇒ session. The body is the shape
     * user-bff's own {@code POST /bff/register} already emits and the shape hugmesh-generator's
     * {@code tests/qemu/seed-accounts.sh} reads ({@code .token}).
     */
    @Test
    void google_invited_ensuresTheAccount_andMintsASession() {
        when(adminBff.allowlistCheck("google", EMAIL)).thenReturn(Mono.just(true));
        when(adminBff.ensureAccount("google", EMAIL))
                .thenReturn(Mono.just(account(GOOGLE_ID, "google", EMAIL, false)));
        when(adminBff.createSession(GOOGLE_ID))
                .thenReturn(Mono.just(new AdminBffInternalClient.SessionView(TOKEN, GOOGLE_ID)));

        postGoogle("{\"email\":\"" + EMAIL + "\"}")
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.token").isEqualTo(TOKEN)
                .jsonPath("$.id").isEqualTo(GOOGLE_ID)
                .jsonPath("$.provider").isEqualTo("google")
                .jsonPath("$.registrationComplete").isEqualTo(false)
                .jsonPath("$.roles[0]").isEqualTo("user");
    }

    @Test
    void discord_invited_ensuresTheAccount_andMintsASession() {
        when(adminBff.allowlistCheck("discord", DISCORD_HANDLE)).thenReturn(Mono.just(true));
        when(adminBff.ensureAccount("discord", DISCORD_HANDLE))
                .thenReturn(Mono.just(account(DISCORD_ID, "discord", DISCORD_HANDLE, false)));
        when(adminBff.createSession(DISCORD_ID))
                .thenReturn(Mono.just(new AdminBffInternalClient.SessionView(TOKEN, DISCORD_ID)));

        postDiscord("{\"username\":\"" + DISCORD_HANDLE + "\"}")
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.token").isEqualTo(TOKEN)
                .jsonPath("$.id").isEqualTo(DISCORD_ID)
                .jsonPath("$.provider").isEqualTo("discord")
                .jsonPath("$.registrationComplete").isEqualTo(false);
    }

    /**
     * The INVITE NAMESPACE is the one admin-bff's allowlist switch understands — {@code google}
     * for an email and {@code discord} for a username. This is the pin that keeps defect 2 of
     * hugmesh-user-bff-api#13 ({@code allowlistCheck("email", …)} ⇒ admin-bff 400 "unknown
     * provider") from being reintroduced on THESE two paths. The handle is lowercased with
     * {@link java.util.Locale#ROOT} before BOTH calls, as admin-bff's
     * {@code str(...).toLowerCase()} does, so the allowlist row and the account key agree —
     * {@code AccountStore} itself lowercases the handle it keys on, so a mixed-case address
     * that skipped this step would consult one allowlist row and create a DIFFERENT account.
     *
     * <p>The {@code Locale.ROOT} is not decoration: a JVM whose default locale is Turkish folds
     * {@code I} to a dotless {@code ı}, so a default-locale {@code toLowerCase()} on this box
     * would key a different account than admin-bff's.
     */
    @Test
    void handle_isLowercased_beforeTheAllowlistLookup_andTheEnsure() {
        when(adminBff.allowlistCheck("google", EMAIL)).thenReturn(Mono.just(true));
        when(adminBff.ensureAccount("google", EMAIL))
                .thenReturn(Mono.just(account(GOOGLE_ID, "google", EMAIL, false)));
        when(adminBff.createSession(GOOGLE_ID))
                .thenReturn(Mono.just(new AdminBffInternalClient.SessionView(TOKEN, GOOGLE_ID)));

        postGoogle("{\"email\":\"Alice@Example.TEST\"}").expectStatus().isOk();

        verify(adminBff).allowlistCheck("google", EMAIL);
        verify(adminBff).ensureAccount("google", EMAIL);
    }

    /**
     * A SPACE-PADDED address is a 400 at the DTO, before the controller's own
     * {@code trim()} ever runs — {@code RegisterEmailRequest.email} is {@code @Email}, and
     * jakarta's {@code @Email} does not trim. <b>This is parity, not a gap:</b> admin-bff's
     * {@code registerGoogle} takes the SAME {@code @Valid RegisterEmailRequest}, so it answers
     * 400 for the same body. Pinned because the controller's defensive {@code trim()} makes it
     * easy to assume otherwise (this test was written asserting 200 and was wrong).
     */
    @Test
    void paddedEmail_is400_atTheDto_sameAsAdminBff() {
        postGoogle("{\"email\":\"  alice@example.test  \"}").expectStatus().isBadRequest();
        verify(adminBff, never()).allowlistCheck(anyString(), anyString());
    }

    // ── The invite gate ───────────────────────────────────────────────────────────────────

    /** admin-bff: {@code ApiException.forbidden("email not invited by an admin")}, raised
     *  BEFORE {@code ensureAccount} — an uninvited caller must never create a row. */
    @Test
    void google_notInvited_is403_andNeverEnsuresAnAccount() {
        when(adminBff.allowlistCheck("google", EMAIL)).thenReturn(Mono.just(false));

        postGoogle("{\"email\":\"" + EMAIL + "\"}")
                .expectStatus().isForbidden()
                .expectBody().jsonPath("$.error").isEqualTo("email not invited by an admin");

        verify(adminBff, never()).ensureAccount(anyString(), anyString());
        verify(adminBff, never()).createSession(anyString());
    }

    @Test
    void discord_notInvited_is403_andNeverEnsuresAnAccount() {
        when(adminBff.allowlistCheck("discord", DISCORD_HANDLE)).thenReturn(Mono.just(false));

        postDiscord("{\"username\":\"" + DISCORD_HANDLE + "\"}")
                .expectStatus().isForbidden()
                .expectBody().jsonPath("$.error")
                .isEqualTo("discord username not invited by an admin");

        verify(adminBff, never()).ensureAccount(anyString(), anyString());
    }

    // ── DECISION 57: the restartOnboarding leg is a 409 ─────────────────────────────────

    /**
     * admin-bff's next call after {@code ensureAccount} is {@code store::restartOnboarding},
     * which is {@code setComplete(a, false)} and nothing else. It is a NO-OP on every input but
     * one: an account that is ALREADY {@code registrationComplete}. admin-bff's
     * {@code /bff/internal/**} surface has no endpoint that can set that column back to false
     * (hugmesh-admin-bff-api#84 is open), and operator decision 57 ruled that input a
     * {@code 409 Conflict} with the existing account — against the recommended "503 until #84
     * lands", which is what this class answered between 2026-09-18 and this revision.
     *
     * <p>The refusal must land BEFORE the mint AND before the usage row: the account is left
     * exactly as it was, no session exists that could be used, and admin-bff's usage table
     * gets no {@code "register"} row for a registration that was not performed. The body is
     * asserted because {@code localpartCollisionFromAdminBff_is409_notAnOpaque500} is also a
     * 409 — a status-only pin could not tell the two apart. Reverting the production line to
     * {@code serviceUnavailable} (the mutation this pin defends) fails here on the status.
     */
    @Test
    void google_alreadyCompleteAccount_is409_andNeverMintsASession() {
        when(adminBff.allowlistCheck("google", EMAIL)).thenReturn(Mono.just(true));
        when(adminBff.ensureAccount("google", EMAIL))
                .thenReturn(Mono.just(account(GOOGLE_ID, "google", EMAIL, true)));
        when(adminBff.createSession(anyString()))
                .thenReturn(Mono.just(new AdminBffInternalClient.SessionView(TOKEN, GOOGLE_ID)));

        postGoogle("{\"email\":\"" + EMAIL + "\"}")
                .expectStatus().isEqualTo(HttpStatus.CONFLICT)
                .expectBody().jsonPath("$.error")
                .value(msg -> assertThat((String) msg)
                        .contains("already completed registration")
                        .contains("decision 57")
                        .doesNotContain("localpart"));

        verify(adminBff, never()).createSession(anyString());
        verify(adminBff, never()).recordUsage(anyString(), anyList(), anyString());
    }

    @Test
    void discord_alreadyCompleteAccount_is409_andNeverMintsASession() {
        when(adminBff.allowlistCheck("discord", DISCORD_HANDLE)).thenReturn(Mono.just(true));
        when(adminBff.ensureAccount("discord", DISCORD_HANDLE))
                .thenReturn(Mono.just(account(DISCORD_ID, "discord", DISCORD_HANDLE, true)));
        when(adminBff.createSession(anyString()))
                .thenReturn(Mono.just(new AdminBffInternalClient.SessionView(TOKEN, DISCORD_ID)));

        postDiscord("{\"username\":\"" + DISCORD_HANDLE + "\"}")
                .expectStatus().isEqualTo(HttpStatus.CONFLICT)
                .expectBody().jsonPath("$.error")
                .value(msg -> assertThat((String) msg).contains("already completed registration"));

        verify(adminBff, never()).createSession(anyString());
        verify(adminBff, never()).recordUsage(anyString(), anyList(), anyString());
    }

    // ── DECISION 55: the usage row ────────────────────────────────────────────────────────

    /**
     * admin-bff's {@code emitAndSession(email, a, "register", …)} records
     * {@code usage.record(handle, a.roles(), action)} — the BARE lowercased handle (not the
     * {@code google:} id), the account's roles VERBATIM (admin-bff's lowercase dialect, which
     * its usage endpoint requires — {@code "ROLE_ADMIN"} would be tagged {@code user}), and the
     * literal {@code "register"}. Same triple here, same position: BEFORE the session mint.
     */
    @Test
    void google_performedRegistration_recordsAdminBffsOwnUsageTriple_beforeTheMint() {
        when(adminBff.allowlistCheck("google", EMAIL)).thenReturn(Mono.just(true));
        when(adminBff.ensureAccount("google", EMAIL))
                .thenReturn(Mono.just(account(GOOGLE_ID, "google", EMAIL, false)));
        when(adminBff.createSession(GOOGLE_ID))
                .thenReturn(Mono.just(new AdminBffInternalClient.SessionView(TOKEN, GOOGLE_ID)));

        postGoogle("{\"email\":\"Alice@Example.TEST\"}").expectStatus().isOk();

        InOrder order = inOrder(adminBff);
        order.verify(adminBff).recordUsage(EMAIL, List.of("user", "matrix", "mastodon"), "register");
        order.verify(adminBff).createSession(GOOGLE_ID);
    }

    @Test
    void discord_performedRegistration_recordsTheUsageTriple_underTheBareHandle() {
        when(adminBff.allowlistCheck("discord", DISCORD_HANDLE)).thenReturn(Mono.just(true));
        when(adminBff.ensureAccount("discord", DISCORD_HANDLE))
                .thenReturn(Mono.just(account(DISCORD_ID, "discord", DISCORD_HANDLE, false)));
        when(adminBff.createSession(DISCORD_ID))
                .thenReturn(Mono.just(new AdminBffInternalClient.SessionView(TOKEN, DISCORD_ID)));

        postDiscord("{\"username\":\"" + DISCORD_HANDLE + "\"}").expectStatus().isOk();

        verify(adminBff).recordUsage(DISCORD_HANDLE, List.of("user", "matrix", "mastodon"), "register");
    }

    /**
     * admin-bff fires the row as {@code .subscribe()} — its outcome never reaches the caller.
     * Same here: a usage failure (admin-bff 5xx, dropped connection, a produce blocking on
     * {@code max.block.ms}) is logged and the registration completes with its session. Turning
     * the detached subscribe into a {@code .then(...)} that propagates (the mutation this pin
     * defends) fails here with a 502.
     */
    @Test
    void usageRowFailure_neverFailsTheRegistration_sessionStillMinted() {
        when(adminBff.allowlistCheck("google", EMAIL)).thenReturn(Mono.just(true));
        when(adminBff.ensureAccount("google", EMAIL))
                .thenReturn(Mono.just(account(GOOGLE_ID, "google", EMAIL, false)));
        when(adminBff.createSession(GOOGLE_ID))
                .thenReturn(Mono.just(new AdminBffInternalClient.SessionView(TOKEN, GOOGLE_ID)));
        when(adminBff.recordUsage(anyString(), anyList(), anyString())).thenReturn(Mono.error(
                WebClientResponseException.create(500, "Internal Server Error", HttpHeaders.EMPTY,
                        new byte[0], null)));

        postGoogle("{\"email\":\"" + EMAIL + "\"}")
                .expectStatus().isOk()
                .expectBody().jsonPath("$.token").isEqualTo(TOKEN);

        verify(adminBff).createSession(GOOGLE_ID);
    }

    /**
     * DETACHED means the response never WAITS on the usage call, not merely that its error is
     * swallowed. Since hugmesh-admin-bff-api PR #104 admin-bff answers
     * {@code POST /bff/internal/usage} only once its write has settled — the Kafka produce,
     * bounded by the producer's {@code max.block.ms} on a broker outage — and the admin-bff
     * {@code WebClient} sets no response timeout, so a chain that AWAITED the call and then
     * swallowed its error ({@code recordUsage(...).onErrorResume(e -> Mono.empty())
     * .then(createSession)}) would pass every error-path pin above while holding each
     * registration for the full produce stall. A usage call that NEVER answers must still let
     * the registration complete, well inside the 3 s the client waits here.
     */
    @Test
    void usageCallThatNeverAnswers_neverDelaysTheRegistration() {
        when(adminBff.allowlistCheck("google", EMAIL)).thenReturn(Mono.just(true));
        when(adminBff.ensureAccount("google", EMAIL))
                .thenReturn(Mono.just(account(GOOGLE_ID, "google", EMAIL, false)));
        when(adminBff.createSession(GOOGLE_ID))
                .thenReturn(Mono.just(new AdminBffInternalClient.SessionView(TOKEN, GOOGLE_ID)));
        when(adminBff.recordUsage(anyString(), anyList(), anyString())).thenReturn(Mono.never());

        client.mutate().responseTimeout(Duration.ofSeconds(3)).build()
                .post().uri("/bff/register/google")
                .contentType(MediaType.APPLICATION_JSON).bodyValue("{\"email\":\"" + EMAIL + "\"}")
                .exchange()
                .expectStatus().isOk()
                .expectBody().jsonPath("$.token").isEqualTo(TOKEN);

        verify(adminBff).recordUsage(EMAIL, List.of("user", "matrix", "mastodon"), "register");
        verify(adminBff).createSession(GOOGLE_ID);
    }

    /**
     * The usage call is made inside the registration chain's {@code flatMap} lambda, so an
     * exception thrown while the client BUILDS its Mono — not an error signal, a plain throw,
     * e.g. {@code List.copyOf} meeting a null roles element — would escape into the response
     * chain as a 500 unless the call is deferred. It must take the same never-fails path as
     * an error signal.
     */
    @Test
    void usageCallThatThrowsSynchronously_neverFailsTheRegistration() {
        when(adminBff.allowlistCheck("google", EMAIL)).thenReturn(Mono.just(true));
        when(adminBff.ensureAccount("google", EMAIL))
                .thenReturn(Mono.just(account(GOOGLE_ID, "google", EMAIL, false)));
        when(adminBff.createSession(GOOGLE_ID))
                .thenReturn(Mono.just(new AdminBffInternalClient.SessionView(TOKEN, GOOGLE_ID)));
        when(adminBff.recordUsage(anyString(), anyList(), anyString()))
                .thenThrow(new NullPointerException("synchronous throw while building the usage call"));

        postGoogle("{\"email\":\"" + EMAIL + "\"}")
                .expectStatus().isOk()
                .expectBody().jsonPath("$.token").isEqualTo(TOKEN);

        verify(adminBff).createSession(GOOGLE_ID);
    }

    /**
     * What a usage failure LEAVES BEHIND: exactly one WARN (not an ERROR, not a silent
     * trace/debug) naming the provider, and never the handle — for the Google leg that is the
     * person's email address, which does not belong in a log line. Captured with a logback
     * {@link ListAppender} on the controller's own logger; the error consumer runs inside the
     * request (the stub's error is synchronous), so the event is there before
     * {@code exchange()} returns. Both the synchronous-throw and the error-signal shapes are
     * covered, because they reach the WARN by different routes.
     */
    @Test
    void usageFailure_isLoggedOnceAtWarn_withTheProvider_neverTheHandle() {
        Logger controllerLog = (Logger) LoggerFactory.getLogger(LegacyPathParityController.class);
        ListAppender<ILoggingEvent> captured = new ListAppender<>();
        captured.start();
        controllerLog.addAppender(captured);
        try {
            when(adminBff.allowlistCheck("google", EMAIL)).thenReturn(Mono.just(true));
            when(adminBff.ensureAccount("google", EMAIL))
                    .thenReturn(Mono.just(account(GOOGLE_ID, "google", EMAIL, false)));
            when(adminBff.createSession(GOOGLE_ID))
                    .thenReturn(Mono.just(new AdminBffInternalClient.SessionView(TOKEN, GOOGLE_ID)));
            when(adminBff.recordUsage(anyString(), anyList(), anyString())).thenReturn(Mono.error(
                    WebClientResponseException.create(500, "Internal Server Error",
                            HttpHeaders.EMPTY, new byte[0], null)));

            postGoogle("{\"email\":\"" + EMAIL + "\"}").expectStatus().isOk();

            List<ILoggingEvent> usageEvents = captured.list.stream()
                    .filter(e -> e.getFormattedMessage().contains("usage row not recorded"))
                    .toList();
            assertThat(usageEvents).as("usage-failure log events").hasSize(1);
            ILoggingEvent event = usageEvents.get(0);
            assertThat(event.getLevel()).isEqualTo(Level.WARN);
            assertThat(event.getFormattedMessage()).contains("[register/google]");
            assertThat(captured.list).as("every event this controller logged")
                    .allSatisfy(e -> {
                        assertThat(e.getLevel()).isNotEqualTo(Level.ERROR);
                        assertThat(e.getFormattedMessage()).doesNotContainIgnoringCase(EMAIL);
                        assertThat(Arrays.deepToString(e.getArgumentArray()))
                                .doesNotContainIgnoringCase(EMAIL);
                    });

            // The synchronous-throw route reaches the same single WARN.
            captured.list.clear();
            when(adminBff.recordUsage(anyString(), anyList(), anyString()))
                    .thenThrow(new NullPointerException("synchronous throw while building the usage call"));
            postGoogle("{\"email\":\"" + EMAIL + "\"}").expectStatus().isOk();
            List<ILoggingEvent> afterThrow = captured.list.stream()
                    .filter(e -> e.getFormattedMessage().contains("usage row not recorded"))
                    .toList();
            assertThat(afterThrow).as("usage-failure events after a synchronous throw").hasSize(1);
            assertThat(afterThrow.get(0).getLevel()).isEqualTo(Level.WARN);
            assertThat(afterThrow.get(0).getFormattedMessage())
                    .contains("[register/google]").doesNotContainIgnoringCase(EMAIL);
            assertThat(Arrays.deepToString(afterThrow.get(0).getArgumentArray()))
                    .doesNotContainIgnoringCase(EMAIL);
        } finally {
            controllerLog.detachAppender(captured);
            captured.stop();
        }
    }

    /** A registration that was NOT performed records nothing — the uninvited 403 and the
     *  localpart-collision 409 (the already-complete 409 is pinned above). */
    @Test
    void refusedRegistrations_recordNoUsageRow() {
        when(adminBff.allowlistCheck("google", EMAIL)).thenReturn(Mono.just(false));
        postGoogle("{\"email\":\"" + EMAIL + "\"}").expectStatus().isForbidden();

        when(adminBff.allowlistCheck("google", EMAIL)).thenReturn(Mono.just(true));
        when(adminBff.ensureAccount("google", EMAIL)).thenReturn(Mono.error(
                WebClientResponseException.create(409, "Conflict", HttpHeaders.EMPTY,
                        new byte[0], null)));
        postGoogle("{\"email\":\"" + EMAIL + "\"}").expectStatus().isEqualTo(HttpStatus.CONFLICT);

        verify(adminBff, never()).recordUsage(anyString(), anyList(), anyString());
    }

    // ── Internal-hop failures ─────────────────────────────────────────────────────────────

    /**
     * admin-bff's {@code persistLocalpart} maps {@code AccountLocalpartService.CollisionException}
     * to a 409. On this side the collision-check runs INSIDE admin-bff's
     * {@code /accounts/ensure} ({@code withLocalpart}), so it arrives as a 409 over the wire —
     * which must be re-raised as a 409 and not flattened into the opaque 500 a raw
     * {@link WebClientResponseException} produces (it is not a
     * {@code ResponseStatusException}).
     */
    @Test
    void localpartCollisionFromAdminBff_is409_notAnOpaque500() {
        when(adminBff.allowlistCheck("google", EMAIL)).thenReturn(Mono.just(true));
        when(adminBff.ensureAccount("google", EMAIL)).thenReturn(Mono.error(
                WebClientResponseException.create(409, "Conflict", HttpHeaders.EMPTY,
                        new byte[0], null)));

        postGoogle("{\"email\":\"" + EMAIL + "\"}")
                .expectStatus().isEqualTo(HttpStatus.CONFLICT);

        verify(adminBff, never()).createSession(anyString());
    }

    /** Any other internal-hop failure is a 502, the same wrap the provision legs apply —
     *  never a 200, and never a 500 that reads like a bug in this BFF. */
    @Test
    void internalHopFailure_is502_andNeverMintsASession() {
        when(adminBff.allowlistCheck("google", EMAIL))
                .thenReturn(Mono.error(new IllegalStateException("admin-bff internal client disabled")));

        postGoogle("{\"email\":\"" + EMAIL + "\"}")
                .expectStatus().isEqualTo(HttpStatus.BAD_GATEWAY);

        verify(adminBff, never()).ensureAccount(anyString(), anyString());
        verify(adminBff, never()).createSession(anyString());
    }

    // ── Body validation, BEFORE any admin-bff call ────────────────────────────────────────

    /** admin-bff's DTOs are {@code @NotBlank}/{@code @Email}; the same DTOs are reused here, so
     *  a malformed body is a clean 400 and the invite gate is never even consulted. */
    @Test
    void blankEmail_is400_beforeAnyAdminBffCall() {
        postGoogle("{\"email\":\"\"}").expectStatus().isBadRequest();
        verify(adminBff, never()).allowlistCheck(anyString(), anyString());
    }

    @Test
    void malformedEmail_is400_beforeAnyAdminBffCall() {
        postGoogle("{\"email\":\"not-an-address\"}").expectStatus().isBadRequest();
        verify(adminBff, never()).allowlistCheck(anyString(), anyString());
    }

    @Test
    void blankDiscordUsername_is400_beforeAnyAdminBffCall() {
        postDiscord("{\"username\":\"\"}").expectStatus().isBadRequest();
        verify(adminBff, never()).allowlistCheck(anyString(), anyString());
    }

    // ── The bff_ cookie ───────────────────────────────────────────────────────────────────

    /** admin-bff mints the opaque session cookie on register; so does user-bff's own
     *  {@code POST /bff/register}. Gated on {@code app.session.cookie.enabled} exactly as
     *  {@code SsoAuthController#emitAndSession} gates it. */
    @Test
    void cookieMode_mintsTheBffSessionCookie() {
        when(cookies.enabled()).thenReturn(true);
        when(cookies.mint(any(), eq(TOKEN)))
                .thenReturn(ResponseCookie.from("bff_session", TOKEN).path("/").httpOnly(true).build());
        when(adminBff.allowlistCheck("google", EMAIL)).thenReturn(Mono.just(true));
        when(adminBff.ensureAccount("google", EMAIL))
                .thenReturn(Mono.just(account(GOOGLE_ID, "google", EMAIL, false)));
        when(adminBff.createSession(GOOGLE_ID))
                .thenReturn(Mono.just(new AdminBffInternalClient.SessionView(TOKEN, GOOGLE_ID)));

        postGoogle("{\"email\":\"" + EMAIL + "\"}")
                .expectStatus().isOk()
                .expectHeader().valueMatches("Set-Cookie", "bff_session=" + TOKEN + ".*");
    }

    /** Cookie mode OFF (the shipped default): no Set-Cookie, and the token still rides in the
     *  body — the carrier hugmesh-generator's qemu seed script reads. */
    @Test
    void cookieModeOff_emitsNoSetCookie_butStillTheBodyToken() {
        when(adminBff.allowlistCheck("google", EMAIL)).thenReturn(Mono.just(true));
        when(adminBff.ensureAccount("google", EMAIL))
                .thenReturn(Mono.just(account(GOOGLE_ID, "google", EMAIL, false)));
        when(adminBff.createSession(GOOGLE_ID))
                .thenReturn(Mono.just(new AdminBffInternalClient.SessionView(TOKEN, GOOGLE_ID)));

        postGoogle("{\"email\":\"" + EMAIL + "\"}")
                .expectStatus().isOk()
                .expectHeader().doesNotExist("Set-Cookie")
                .expectBody().jsonPath("$.token").isEqualTo(TOKEN);
    }

    // ── The account these paths create must be reachable by the session that follows ──────

    /**
     * The retraction on hugmesh-admin-bff-api#2 (2026-09-17) that applies to THIS issue: a
     * {@code google:}/{@code discord:} session is exactly what these two handlers bring into
     * existence, and {@code CanonicalIdentityResolver.ownAccountId} used to resolve such a
     * principal to {@code casdoor:<handle>} and 401 every legacy-parity path. This pins the
     * round trip end to end — take the {@code id} these handlers emit, build the synthetic
     * principal EXACTLY as {@code BffSessionAuthenticationWebFilter.syntheticJwt} builds it for
     * that account (including the {@code email}/{@code preferred_username} claim that used to
     * win the derivation, and the EMPTY roles claim a not-yet-complete registration carries),
     * and assert the resolver hands back the same id. A {@code casdoor:}-only pin rides a
     * principal these paths never produce.
     */
    @Test
    void theAccountsTheseHandlersCreate_resolveBackToThemselves_onTheBffCarrier() {
        assertThat(CanonicalIdentityResolver.ownAccountId(
                syntheticPrincipalFor(GOOGLE_ID, "google", EMAIL))).isEqualTo(GOOGLE_ID);
        assertThat(CanonicalIdentityResolver.ownAccountId(
                syntheticPrincipalFor(DISCORD_ID, "discord", DISCORD_HANDLE))).isEqualTo(DISCORD_ID);
        // The third namespace, for contrast: a native-login account is keyed casdoor:<subject>
        // and must resolve to ITSELF too — these register paths never create one (the provider
        // is a literal), so it is pinned here only to prove the resolver is not google-shaped.
        assertThat(CanonicalIdentityResolver.ownAccountId(
                syntheticPrincipalFor("casdoor:bob", "casdoor", "bob"))).isEqualTo("casdoor:bob");
    }

    /** {@code BffSessionAuthenticationWebFilter.syntheticJwt}'s shape for a freshly registered
     *  (therefore NOT registrationComplete, therefore empty-roles) account. */
    private static Jwt syntheticPrincipalFor(String accountId, String provider, String handle) {
        Jwt.Builder b = Jwt.withTokenValue(
                        BffSessionAuthenticationWebFilter.SYNTHETIC_TOKEN_MARKER + accountId)
                .header("typ", "bff-synthetic-principal")
                .subject(accountId)
                .claim("roles", List.of());
        if ("google".equalsIgnoreCase(provider)) {
            b.claim("email", handle);
        } else {
            b.claim("preferred_username", handle);
        }
        return b.build();
    }
}
