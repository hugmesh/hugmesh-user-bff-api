package net.hugmesh.userbff.reset;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import net.hugmesh.commons.web.ApiException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * {@link PasswordResetService} is the POLICY layer, and policy here is almost entirely
 * about REFUSAL — so that is what this class weighs most heavily.
 *
 * <p>Three properties are load-bearing and each is asserted from both sides:
 * <ol>
 *   <li>the request leg is INDISTINGUISHABLE for a known and an unknown username
 *       (otherwise this permitAll endpoint is a membership oracle);</li>
 *   <li>the confirm leg gives ONE answer for every identity/code refusal, and in
 *       particular never lets Casdoor's own wording through;</li>
 *   <li>the DARK 503 is the single exception to both — a fact about the service, not
 *       about an account, and masking it would strand the user in a loop.</li>
 * </ol>
 */
class PasswordResetServiceTest {

    private static final int MIN_LEN = 8;

    private PasswordResetService service(CasdoorPasswordResetClient casdoor) {
        return new PasswordResetService(casdoor, MIN_LEN);
    }

    private static ApiException dark() {
        return ApiException.serviceUnavailable("password reset is not enabled on this mesh");
    }

    // ══ 1. THE REQUEST LEG IS NOT AN ENUMERATION ORACLE ══════════════════════

    @Test
    void request_knownUser_completes() {
        CasdoorPasswordResetClient casdoor = mock(CasdoorPasswordResetClient.class);
        when(casdoor.sendResetCode("alice")).thenReturn(Mono.empty());

        StepVerifier.create(service(casdoor).request("alice")).verifyComplete();
        verify(casdoor).sendResetCode("alice");
    }

    /**
     * THE HEADLINE REFUSAL TEST. Casdoor refuses an unknown user; the service must still
     * complete, so the controller's fixed 202 is byte-identical to the known-user case.
     */
    @Test
    void request_unknownUser_stillCompletes_soTheTwoCasesAreIndistinguishable() {
        CasdoorPasswordResetClient casdoor = mock(CasdoorPasswordResetClient.class);
        when(casdoor.sendResetCode("nobody"))
                .thenReturn(Mono.error(ApiException.badRequest("the user: hugmesh/nobody doesn't exist")));

        StepVerifier.create(service(casdoor).request("nobody")).verifyComplete();
    }

    /** A transport failure (Casdoor unreachable) is ALSO swallowed on the request leg —
     *  it would otherwise be a second, subtler oracle (timeouts only for real accounts). */
    @Test
    void request_transportFailure_stillCompletes() {
        CasdoorPasswordResetClient casdoor = mock(CasdoorPasswordResetClient.class);
        when(casdoor.sendResetCode("alice"))
                .thenReturn(Mono.error(new IllegalStateException("connection refused")));

        StepVerifier.create(service(casdoor).request("alice")).verifyComplete();
    }

    /** The DARK 503 is the ONE thing that must NOT be flattened: it is identical for every
     *  visitor, reveals nothing, and hiding it makes a locked-out user retry forever. */
    @Test
    void request_darkSurface_propagates503_ratherThanAPolite202() {
        CasdoorPasswordResetClient casdoor = mock(CasdoorPasswordResetClient.class);
        when(casdoor.sendResetCode("alice")).thenReturn(Mono.error(dark()));

        StepVerifier.create(service(casdoor).request("alice"))
                .verifyErrorSatisfies(t -> assertThat(((ApiException) t).status())
                        .isEqualTo(HttpStatus.SERVICE_UNAVAILABLE));
    }

    @Test
    void request_blankUsername_is400_andNeverCallsCasdoor() {
        CasdoorPasswordResetClient casdoor = mock(CasdoorPasswordResetClient.class);

        assertThatThrownBy(() -> service(casdoor).request("   ").block())
                .isInstanceOf(ApiException.class)
                .hasMessageContaining("username required");
        verify(casdoor, never()).sendResetCode(anyString());
    }

    @Test
    void request_trimsTheUsername_beforeAddressingTheIdP() {
        CasdoorPasswordResetClient casdoor = mock(CasdoorPasswordResetClient.class);
        when(casdoor.sendResetCode("alice")).thenReturn(Mono.empty());

        service(casdoor).request("  alice  ").block();
        verify(casdoor).sendResetCode("alice");
    }

    // ══ 2. THE CONFIRM LEG GIVES ONE ANSWER FOR EVERY IDENTITY/CODE REFUSAL ══

    @Test
    void confirm_success_completes() {
        CasdoorPasswordResetClient casdoor = mock(CasdoorPasswordResetClient.class);
        when(casdoor.resetPassword("alice", "123456", "s3cret-enough")).thenReturn(Mono.empty());

        StepVerifier.create(service(casdoor).confirm("alice", "123456", "s3cret-enough"))
                .verifyComplete();
        verify(casdoor).resetPassword("alice", "123456", "s3cret-enough");
    }

    /**
     * CASDOOR'S WORDING MUST NOT SURVIVE. "the user doesn't exist" would tell an attacker
     * that the username half of their guess was wrong — the very oracle the request leg
     * closes. Asserted as an ABSENCE, because that is the property that matters.
     */
    @Test
    void confirm_unknownUser_isFlattened_andLeaksNoCasdoorWording() {
        CasdoorPasswordResetClient casdoor = mock(CasdoorPasswordResetClient.class);
        when(casdoor.resetPassword(anyString(), anyString(), anyString()))
                .thenReturn(Mono.error(ApiException.badRequest(
                        "identity provider refused set-password(reset): the user: hugmesh/nobody doesn't exist")));

        assertThatThrownBy(() -> service(casdoor).confirm("nobody", "123456", "s3cret-enough").block())
                .isInstanceOf(ApiException.class)
                .hasMessageNotContaining("doesn't exist")
                .hasMessageNotContaining("nobody")
                .hasMessageContaining("could not complete that reset");
    }

    /**
     * A WRONG CODE MUST READ IDENTICALLY TO AN UNKNOWN USER. This pair is the whole point:
     * if the two messages ever diverge, the oracle is back.
     */
    @Test
    void confirm_wrongCode_producesTheSameMessageAsAnUnknownUser() {
        CasdoorPasswordResetClient unknownUser = mock(CasdoorPasswordResetClient.class);
        when(unknownUser.resetPassword(anyString(), anyString(), anyString()))
                .thenReturn(Mono.error(ApiException.badRequest("the user: hugmesh/nobody doesn't exist")));
        CasdoorPasswordResetClient wrongCode = mock(CasdoorPasswordResetClient.class);
        when(wrongCode.resetPassword(anyString(), anyString(), anyString()))
                .thenReturn(Mono.error(ApiException.badRequest(
                        "password or code is incorrect, you have 4 remaining chances")));

        String unknownMessage = messageOf(() ->
                service(unknownUser).confirm("nobody", "123456", "s3cret-enough").block());
        String wrongCodeMessage = messageOf(() ->
                service(wrongCode).confirm("alice", "000000", "s3cret-enough").block());

        assertThat(wrongCodeMessage).isEqualTo(unknownMessage);
        // And in particular the count of remaining chances — a genuine brute-force aid —
        // never reaches the browser.
        assertThat(wrongCodeMessage).doesNotContain("remaining chances");
    }

    /**
     * REGRESSION GUARD for a bug this class was written with and then fixed. An earlier
     * draft let "password policy" refusals through by substring-matching Casdoor's message
     * for the word "password". Casdoor's own documented WRONG-CODE message is "password or
     * code is incorrect…", so that heuristic leaked precisely the refusal it was meant to
     * hide. No message inspection happens any more, and this pins that.
     */
    @Test
    void confirm_casdoorMessageContainingTheWordPassword_isStillFlattened() {
        CasdoorPasswordResetClient casdoor = mock(CasdoorPasswordResetClient.class);
        when(casdoor.resetPassword(anyString(), anyString(), anyString()))
                .thenReturn(Mono.error(ApiException.badRequest(
                        "identity provider refused set-password(reset): "
                                + "password or code is incorrect, you have 4 remaining chances")));

        assertThatThrownBy(() -> service(casdoor).confirm("alice", "000000", "s3cret-enough").block())
                .isInstanceOf(ApiException.class)
                .hasMessageNotContaining("incorrect")
                .hasMessageNotContaining("remaining");
    }

    /** A raw transport failure must not surface a stack trace or a connection string. */
    @Test
    void confirm_transportFailure_isFlattenedToo() {
        CasdoorPasswordResetClient casdoor = mock(CasdoorPasswordResetClient.class);
        when(casdoor.resetPassword(anyString(), anyString(), anyString()))
                .thenReturn(Mono.error(new IllegalStateException(
                        "connection refused: casdoor.hugmesh-pki.svc.cluster.local:8000")));

        assertThatThrownBy(() -> service(casdoor).confirm("alice", "123456", "s3cret-enough").block())
                .isInstanceOf(ApiException.class)
                .hasMessageNotContaining("cluster.local")
                .hasMessageContaining("could not complete that reset");
    }

    @Test
    void confirm_darkSurface_propagates503_notA400() {
        CasdoorPasswordResetClient casdoor = mock(CasdoorPasswordResetClient.class);
        when(casdoor.resetPassword(anyString(), anyString(), anyString())).thenReturn(Mono.error(dark()));

        StepVerifier.create(service(casdoor).confirm("alice", "123456", "s3cret-enough"))
                .verifyErrorSatisfies(t -> assertThat(((ApiException) t).status())
                        .isEqualTo(HttpStatus.SERVICE_UNAVAILABLE));
    }

    // ══ 3. LOCAL VALIDATION RUNS FIRST — NEVER BURN THE ONE-TIME CODE ════════

    @Test
    void confirm_blankCode_is400_andNeverCallsCasdoor() {
        CasdoorPasswordResetClient casdoor = mock(CasdoorPasswordResetClient.class);

        assertThatThrownBy(() -> service(casdoor).confirm("alice", "  ", "s3cret-enough").block())
                .isInstanceOf(ApiException.class)
                .hasMessageContaining("code required");
        verify(casdoor, never()).resetPassword(anyString(), anyString(), anyString());
    }

    @Test
    void confirm_blankNewPassword_is400_andNeverCallsCasdoor() {
        CasdoorPasswordResetClient casdoor = mock(CasdoorPasswordResetClient.class);

        assertThatThrownBy(() -> service(casdoor).confirm("alice", "123456", "   ").block())
                .isInstanceOf(ApiException.class)
                .hasMessageContaining("newPassword required");
        verify(casdoor, never()).resetPassword(anyString(), anyString(), anyString());
    }

    /**
     * A short password is refused LOCALLY and SPECIFICALLY — the one password-quality rule
     * the user is told, because it is about the string they just typed and reveals nothing
     * about any account. Critically, Casdoor is never called, so the one-time code is not
     * consumed by an attempt that could not have succeeded.
     */
    @Test
    void confirm_tooShortPassword_is400_named_andNeverBurnsTheCode() {
        CasdoorPasswordResetClient casdoor = mock(CasdoorPasswordResetClient.class);

        assertThatThrownBy(() -> service(casdoor).confirm("alice", "123456", "short").block())
                .isInstanceOf(ApiException.class)
                .hasMessageContaining("at least 8 characters");
        verify(casdoor, never()).resetPassword(anyString(), anyString(), anyString());
    }

    @Test
    void confirm_exactlyMinLength_isAccepted() {
        CasdoorPasswordResetClient casdoor = mock(CasdoorPasswordResetClient.class);
        when(casdoor.resetPassword("alice", "123456", "12345678")).thenReturn(Mono.empty());

        StepVerifier.create(service(casdoor).confirm("alice", "123456", "12345678")).verifyComplete();
    }

    @Test
    void confirm_blankUsername_is400_andNeverCallsCasdoor() {
        CasdoorPasswordResetClient casdoor = mock(CasdoorPasswordResetClient.class);

        assertThatThrownBy(() -> service(casdoor).confirm(null, "123456", "s3cret-enough").block())
                .isInstanceOf(ApiException.class)
                .hasMessageContaining("username required");
        verify(casdoor, never()).resetPassword(anyString(), anyString(), anyString());
    }

    // ── enabled() mirrors the client, so the surface can report its own state ──

    @Test
    void enabled_mirrorsTheClient() {
        CasdoorPasswordResetClient on = mock(CasdoorPasswordResetClient.class);
        when(on.enabled()).thenReturn(true);
        CasdoorPasswordResetClient off = mock(CasdoorPasswordResetClient.class);
        when(off.enabled()).thenReturn(false);

        assertThat(service(on).enabled()).isTrue();
        assertThat(service(off).enabled()).isFalse();
    }

    private static String messageOf(Runnable r) {
        try {
            r.run();
            throw new AssertionError("expected a refusal");
        } catch (ApiException e) {
            return e.getMessage();
        }
    }
}
