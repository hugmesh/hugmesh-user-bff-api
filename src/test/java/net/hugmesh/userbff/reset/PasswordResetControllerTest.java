package net.hugmesh.userbff.reset;

import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;
import net.hugmesh.commons.web.ApiException;
import net.hugmesh.userbff.web.ApiExceptionHandler;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * HTTP-level contract for {@link PasswordResetController}, bound with the REAL
 * {@link ApiExceptionHandler} so an {@link ApiException} maps to its true status exactly
 * as in production (the {@code ConnectedClientsControllerCrossDomainTest} idiom) and
 * {@code @Valid} body constraints render their real 400.
 *
 * <p>What this class proves is mostly what the endpoint REFUSES to say. The two response
 * bodies are asserted as FIXED strings on purpose: the anti-enumeration property lives in
 * their sameness, and a well-meaning future edit that made the 202 friendlier ("we've
 * emailed alice@…") would break the property without breaking anything else.
 */
class PasswordResetControllerTest {

    private WebTestClient client(PasswordResetService service) {
        return WebTestClient.bindToController(new PasswordResetController(service))
                .controllerAdvice(new ApiExceptionHandler())
                .build();
    }

    private static String requestBody(String username) {
        return "{\"username\":\"" + username + "\"}";
    }

    private static String confirmBody(String username, String code, String newPassword) {
        return "{\"username\":\"" + username + "\",\"code\":\"" + code
                + "\",\"newPassword\":\"" + newPassword + "\"}";
    }

    // ── request: ALWAYS 202, ALWAYS the same body ─────────────────────────────

    @Test
    void request_knownUser_is202_withTheFixedBody() {
        PasswordResetService service = mock(PasswordResetService.class);
        when(service.request("alice")).thenReturn(Mono.empty());

        client(service).post().uri("/bff/password-reset/request")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(requestBody("alice"))
                .exchange()
                .expectStatus().isAccepted()
                .expectBody()
                .jsonPath("$.op").isEqualTo("password-reset-request")
                .jsonPath("$.status").isEqualTo("accepted");
    }

    /**
     * THE PROPERTY. The service flattens an unknown user to a completion, so the wire
     * response for a non-existent account is identical to a real one — same status, same
     * body, no extra field. Asserted here at the HTTP layer, where an attacker actually
     * observes it.
     */
    @Test
    void request_unknownUser_isTheIdenticalAcceptedResponse() {
        PasswordResetService service = mock(PasswordResetService.class);
        when(service.request("nobody")).thenReturn(Mono.empty());   // service already flattened it

        client(service).post().uri("/bff/password-reset/request")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(requestBody("nobody"))
                .exchange()
                .expectStatus().isAccepted()
                .expectBody()
                .jsonPath("$.op").isEqualTo("password-reset-request")
                .jsonPath("$.status").isEqualTo("accepted")
                // No field may vary with account existence — not even a hint.
                .jsonPath("$.username").doesNotExist()
                .jsonPath("$.email").doesNotExist()
                .jsonPath("$.sent").doesNotExist();
    }

    @Test
    void request_darkSurface_is503_notAPolite202() {
        PasswordResetService service = mock(PasswordResetService.class);
        when(service.request("alice")).thenReturn(Mono.error(
                ApiException.serviceUnavailable("password reset is not enabled on this mesh")));

        client(service).post().uri("/bff/password-reset/request")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(requestBody("alice"))
                .exchange()
                .expectStatus().isEqualTo(503)
                .expectBody().jsonPath("$.error").value(org.hamcrest.Matchers.containsString("not enabled"));
    }

    @Test
    void request_missingUsername_is400_andNeverCallsTheService() {
        PasswordResetService service = mock(PasswordResetService.class);

        client(service).post().uri("/bff/password-reset/request")
                .contentType(MediaType.APPLICATION_JSON).bodyValue("{}")
                .exchange()
                .expectStatus().isBadRequest()
                .expectBody().jsonPath("$.fields.username").isEqualTo("username is required");

        verify(service, never()).request(anyString());
    }

    @Test
    void request_blankUsername_is400_andNeverCallsTheService() {
        PasswordResetService service = mock(PasswordResetService.class);

        client(service).post().uri("/bff/password-reset/request")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(requestBody("   "))
                .exchange()
                .expectStatus().isBadRequest();

        verify(service, never()).request(anyString());
    }

    // ── confirm: 200 ONLY on a real IdP write ────────────────────────────────

    @Test
    void confirm_success_is200() {
        PasswordResetService service = mock(PasswordResetService.class);
        when(service.confirm("alice", "123456", "s3cret-enough")).thenReturn(Mono.empty());

        client(service).post().uri("/bff/password-reset/confirm")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(confirmBody("alice", "123456", "s3cret-enough"))
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.op").isEqualTo("password-reset-confirm")
                .jsonPath("$.status").isEqualTo("reset");
    }

    /**
     * A REFUSED reset must be a 400 carrying the single non-revealing message — NEVER a
     * 200 with a "queued" acknowledgement. This is the same class of defect the sibling
     * change-password client was fixed for ("reported success while the password never
     * changed"), and it is worse here: the user would go on to try signing in with a
     * password that was never set.
     */
    @Test
    void confirm_refused_is400_notASuccessAcknowledgement() {
        PasswordResetService service = mock(PasswordResetService.class);
        when(service.confirm("alice", "000000", "s3cret-enough")).thenReturn(Mono.error(
                ApiException.badRequest("we could not complete that reset — the code may have expired")));

        client(service).post().uri("/bff/password-reset/confirm")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(confirmBody("alice", "000000", "s3cret-enough"))
                .exchange()
                .expectStatus().isBadRequest()
                .expectBody()
                .jsonPath("$.status").doesNotExist()
                .jsonPath("$.error").value(org.hamcrest.Matchers.containsString("could not complete"));
    }

    @Test
    void confirm_darkSurface_is503() {
        PasswordResetService service = mock(PasswordResetService.class);
        when(service.confirm(anyString(), anyString(), anyString())).thenReturn(Mono.error(
                ApiException.serviceUnavailable("password reset is not enabled on this mesh")));

        client(service).post().uri("/bff/password-reset/confirm")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(confirmBody("alice", "123456", "s3cret-enough"))
                .exchange()
                .expectStatus().isEqualTo(503);
    }

    @Test
    void confirm_missingCode_is400_andNeverCallsTheService() {
        PasswordResetService service = mock(PasswordResetService.class);

        client(service).post().uri("/bff/password-reset/confirm")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"username\":\"alice\",\"newPassword\":\"s3cret-enough\"}")
                .exchange()
                .expectStatus().isBadRequest()
                .expectBody().jsonPath("$.fields.code").isEqualTo("code is required");

        verify(service, never()).confirm(anyString(), anyString(), anyString());
    }

    @Test
    void confirm_missingNewPassword_is400_andNeverCallsTheService() {
        PasswordResetService service = mock(PasswordResetService.class);

        client(service).post().uri("/bff/password-reset/confirm")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"username\":\"alice\",\"code\":\"123456\"}")
                .exchange()
                .expectStatus().isBadRequest()
                .expectBody().jsonPath("$.fields.newPassword").isEqualTo("newPassword is required");

        verify(service, never()).confirm(anyString(), anyString(), anyString());
    }

    /**
     * CROSS-USER ATTEMPT. There is no owner to enforce here — the caller is anonymous by
     * construction — so the control is that possession of the CODE is the only authority,
     * and the code belongs to whatever account Casdoor mailed it to. This test pins the
     * consequence: naming someone else's username buys nothing, because the request is
     * passed through verbatim and Casdoor refuses a code that was not issued for it. What
     * the controller must NOT do is accept an owner override from the body — asserted by
     * the fact that the ONLY identity input is the username field itself.
     */
    @Test
    void confirm_ignoresAnyExtraOwnerFieldInTheBody() {
        PasswordResetService service = mock(PasswordResetService.class);
        when(service.confirm("alice", "123456", "s3cret-enough")).thenReturn(Mono.empty());

        client(service).post().uri("/bff/password-reset/confirm")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"username\":\"alice\",\"code\":\"123456\","
                        + "\"newPassword\":\"s3cret-enough\",\"owner\":\"bob\",\"userOwner\":\"bob\"}")
                .exchange()
                .expectStatus().isOk();

        // "bob" reached nothing: the service was addressed with alice and only alice.
        verify(service).confirm("alice", "123456", "s3cret-enough");
        verify(service, never()).confirm(org.mockito.ArgumentMatchers.eq("bob"), anyString(), anyString());
    }
}
