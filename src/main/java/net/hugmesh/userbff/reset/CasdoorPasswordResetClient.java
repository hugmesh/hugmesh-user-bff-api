package net.hugmesh.userbff.reset;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import net.hugmesh.commons.web.ApiException;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The ANONYMOUS "I forgot my password" leg against the Casdoor IdP — the sibling of
 * {@link net.hugmesh.userbff.profile.CasdoorUserClient}, which only ever serves the
 * AUTHENTICATED change (it requires the caller's CURRENT password and a live JWT, so
 * it is unreachable by definition for someone who is locked out).
 *
 * <p>Two calls, both server-side, both over the INTERNAL Casdoor base — Casdoor is
 * NEVER browser-exposed and its hosted reset UI is deliberately unroutable from the
 * front door (hugmesh-generator {@code tests/stack/gateway-routes/fe/application-routes.yml}):
 * <ul>
 *   <li>{@link #sendResetCode} — {@code POST /api/send-verification-code}, which asks
 *       Casdoor to mail a one-time code to the address IT holds for the account. The
 *       destination is never supplied by, or echoed to, the caller: the browser sends
 *       only a username, so this endpoint cannot be used to mail an attacker-chosen
 *       address, and it cannot leak the account's real email either.</li>
 *   <li>{@link #resetPassword} — {@code POST /api/set-password} carrying {@code code}
 *       INSTEAD of {@code oldPassword}. Casdoor verifies the code server-side; a wrong
 *       or expired code is refused there, so this BFF never holds or judges the secret.</li>
 * </ul>
 *
 * <h2>WIRE SHAPE: NOT LIVE-VERIFIED (unlike its sibling)</h2>
 *
 * <p>{@code CasdoorUserClient}'s javadoc pins shapes that were live-verified in 2026-07
 * against a running Casdoor. THESE TWO WERE NOT — no Casdoor was reachable when this was
 * written, and a wrong field name here fails CLOSED (Casdoor answers
 * {@code {"status":"error"}} and {@link #requireOk} turns that into a refusal) rather
 * than silently succeeding. That is precisely why the whole surface
 * {@linkplain PasswordResetConfig SHIPS DARK} behind {@code casdoor.password-reset.enabled}
 * (default {@code false}): flipping it on is an explicit act that should be paired with
 * the live check below, against {@code casbin/casdoor:3.80.0}:
 *
 * <pre>
 *   curl -su "$CLIENT_ID:$CLIENT_SECRET" http://casdoor:8000/api/send-verification-code \
 *        -d method=forget -d type=email -d applicationId=admin/app-user-bff -d checkUser=alice
 *   curl -su "$CLIENT_ID:$CLIENT_SECRET" http://casdoor:8000/api/set-password \
 *        -d userOwner=hugmesh -d userName=alice -d code=123456 -d newPassword=...
 * </pre>
 *
 * <p>The forms are built in ONE place each ({@link #sendResetCode} / {@link #resetPassword})
 * and pinned by {@code CasdoorPasswordResetClientTest}, so correcting a field name after a
 * live check is a one-line change with a test that moves with it.
 *
 * <p>DELIVERY IS A SEPARATE PRECONDITION. Casdoor mails the code over SMTP, and SMTP is
 * absent-by-default in this platform (hugmesh-generator
 * {@code specs/cluster/manifests/casdoor/app-conf-configmap.yaml}: "When that secret is
 * ABSENT the env vars are unset"). With no SMTP, {@code send-verification-code} cannot
 * deliver anything — so this client being live is necessary but NOT sufficient; see the
 * repo README section this class is cross-referenced from.
 *
 * <p>NEVER LOGGED: the verification code and the new password are secrets and appear in
 * no log statement here, at any level.
 */
public class CasdoorPasswordResetClient {

    private static final Logger log = LoggerFactory.getLogger(CasdoorPasswordResetClient.class);

    /** Casdoor's {@code method} discriminator for the forgot-password verification flow. */
    private static final String METHOD_FORGET = "forget";
    /** Casdoor's {@code type} discriminator — the code is mailed, not SMS'd. */
    private static final String TYPE_EMAIL = "email";

    /** Null unless casdoor.password-reset.enabled=true — when null every call FAILS CLOSED. */
    private final WebClient http;
    private final String organization;
    /** Casdoor addresses an application as {@code <owner>/<name>}; the owner is always
     *  {@code admin} for a Casdoor-registered application (not the user organization). */
    private final String applicationId;

    public CasdoorPasswordResetClient(WebClient http, String organization, String applicationId) {
        this.http = http;
        this.organization = organization;
        this.applicationId = applicationId;
    }

    /** Whether the live reset client is wired (vs. the fail-closed dark stub). */
    public boolean enabled() { return http != null; }

    /**
     * Ask Casdoor to mail a one-time reset code to the address it holds for
     * {@code username}. The destination is Casdoor's business: this BFF never learns
     * it, so the response cannot be turned into an email-disclosure oracle.
     *
     * <p>An unknown user is refused by Casdoor and surfaces here as a 400
     * {@link ApiException} — the CALLER ({@link PasswordResetService}) is what decides
     * whether that distinction reaches the browser, and it deliberately does not.
     */
    public Mono<Void> sendResetCode(String username) {
        if (http == null) {
            return darkError("send-verification-code");
        }
        return http.post()
                .uri("/api/send-verification-code")
                .body(BodyInserters.fromFormData(form(Map.of(
                        "applicationId", applicationId,
                        "method", METHOD_FORGET,
                        "type", TYPE_EMAIL,
                        "checkUser", username,
                        "dest", username,
                        "organization", organization))))
                .retrieve()
                .bodyToMono(Map.class)
                .flatMap(r -> requireOk("send-verification-code", username, r))
                .then();
    }

    /**
     * Set {@code username}'s password using the mailed {@code code} in place of the
     * current password. Casdoor verifies the code; a wrong/expired one comes back as
     * {@code {"status":"error"}} and becomes a 400 here — NEVER a success
     * acknowledgement (the exact "reported success but nothing changed" failure the
     * sibling client's {@code requireOk} exists to prevent).
     *
     * <p>{@code oldPassword} is deliberately absent from this form: supplying an empty
     * one alongside a code is what makes Casdoor fall back to password verification and
     * refuse. The code IS the second factor.
     */
    public Mono<Void> resetPassword(String username, String code, String newPassword) {
        if (http == null) {
            return darkError("set-password");
        }
        return http.post()
                .uri("/api/set-password")
                .body(BodyInserters.fromFormData(form(Map.of(
                        "userOwner", organization,
                        "userName", username,
                        "code", code == null ? "" : code,
                        "newPassword", newPassword == null ? "" : newPassword))))
                .retrieve()
                .bodyToMono(Map.class)
                .flatMap(r -> requireOk("set-password(reset)", username, r))
                .then();
    }

    /**
     * FAIL CLOSED while the surface is dark — a 503, never an empty success. This is a
     * deliberate DIVERGENCE from {@code CasdoorUserClient}'s stub, which logs and
     * completes: that client is reached only by an ALREADY-AUTHENTICATED caller who can
     * see the {@code "casdoor":"stubbed"} field in its acknowledgement, whereas a
     * locked-out visitor here would read a silent completion as "the mail is coming"
     * and wait forever for a code that was never requested.
     */
    private static Mono<Void> darkError(String op) {
        log.debug("[casdoor-reset] {} refused — password reset is dark "
                + "(casdoor.password-reset.enabled=false)", op);
        return Mono.error(ApiException.serviceUnavailable(
                "password reset is not enabled on this mesh"));
    }

    /** Casdoor's set-password/send-verification-code read urlencoded FORM fields only
     *  (a JSON body of the same fields is rejected — live-verified for set-password in
     *  {@code CasdoorUserClient}), so both calls above MUST stay fromFormData. */
    private static MultiValueMap<String, String> form(Map<String, String> fields) {
        // LinkedHashMap first so the emitted form field ORDER is deterministic — Map.of
        // is deliberately order-randomised, which would make the recorded-body
        // assertions in the tests flaky.
        Map<String, String> ordered = new LinkedHashMap<>(fields);
        LinkedMultiValueMap<String, String> mv = new LinkedMultiValueMap<>();
        ordered.forEach(mv::add);
        return mv;
    }

    /**
     * Casdoor answers HTTP 200 for REFUSED operations too, carrying
     * {@code {"status":"error","msg":...}} — so the HTTP status alone is meaningless and
     * the body's {@code status} is the real outcome. Identical in shape to
     * {@code CasdoorUserClient.requireOk} and identical in purpose: a refusal must never
     * become a success acknowledgement.
     */
    private static Mono<Map<?, ?>> requireOk(String op, String subject, Map<?, ?> response) {
        if (response != null && "ok".equals(response.get("status"))) {
            return Mono.just(response);
        }
        Object msg = response == null ? null : response.get("msg");
        String detail = (msg == null || String.valueOf(msg).isBlank())
                ? "no error message from the IdP" : String.valueOf(msg);
        log.warn("[casdoor-reset] {} for {} REFUSED by Casdoor: {}", op, subject, detail);
        return Mono.error(ApiException.badRequest("identity provider refused " + op + ": " + detail));
    }
}
