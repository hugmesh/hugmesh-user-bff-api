package net.hugmesh.userbff.profile;

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
 * Reactive wrapper around the Casdoor IdP "change my own credentials" surface.
 * Password + email are owned by Casdoor (the identity provider), NOT by this BFF's
 * {@code user_profile} table, so a self-service password/email change must go to
 * Casdoor — the BFF never stores credentials.
 *
 * <p>✅ CONFIRMED Casdoor endpoints — live-verified 2026-07 against the running
 * compose-stack Casdoor ({@code casbin/casdoor}, Basic client-credential auth,
 * seeded org {@code hugmesh}):
 * <ul>
 *   <li>password: {@code POST /api/set-password}, body MUST be
 *       {@code application/x-www-form-urlencoded} with fields {@code userOwner},
 *       {@code userName}, {@code oldPassword}, {@code newPassword}. A JSON body of
 *       the same fields is REJECTED ({@code {"status":"error","msg":"The user: /
 *       doesn't exist"}} — Casdoor reads only the form). {@code oldPassword} IS
 *       verified even under admin/client-credential Basic auth (wrong old →
 *       {@code status:"error"}, {@code msg:"password or code is incorrect, you
 *       have N remaining chances"}). Success → {@code {"status":"ok"}}.</li>
 *   <li>email: {@code POST /api/update-user?id=<org>/<name>&columns=email} with a
 *       PARTIAL user object {@code {owner,name,email}}. The {@code columns=email}
 *       param is REQUIRED for the partial shape: without it Casdoor validates the
 *       body as a FULL user object and rejects it ({@code {"status":"error",
 *       "msg":"Display name cannot be empty"}}). With it only the email column is
 *       written and every other field is preserved (live-verified). Success →
 *       {@code {"status":"ok","data":"Affected"}}. (Casdoor has no narrower
 *       "set-email" call; the verification flow via
 *       {@code /api/send-verification-code} + {@code /api/verify-code} remains the
 *       production hardening path.)</li>
 * </ul>
 *
 * <p>Auth (live-verified): BOTH the service client-credential Basic auth (what
 * {@code CasdoorUserConfig} wires) and the caller's own password-grant bearer are
 * accepted for the caller's OWN user; a user bearer aimed at ANOTHER user gets
 * {@code "Unauthorized operation"}. The BFF's JWT-claim-derived {@code username}
 * (the token's {@code preferred_username} — Casdoor's login name — never a request
 * field) plus Casdoor's own oldPassword check keep the service credential from
 * being a cross-user escalation on the password path.
 *
 * <p>GATING: the actual HTTP call remains OFF by default (a configured
 * {@link WebClient} is only present when {@code casdoor.account.enabled=true}).
 * When disabled the reactive flow is still fully wired: the controller -> service
 * -> this client chain runs and returns a "queued" acknowledgement WITHOUT a live
 * Casdoor write. The HTTP shapes below are the live-confirmed ones (see README).
 */
public class CasdoorUserClient {

    private static final Logger log = LoggerFactory.getLogger(CasdoorUserClient.class);

    /** Null unless casdoor.account.enabled=true — when null every call is a documented no-op stub. */
    private final WebClient http;
    private final String organization;

    public CasdoorUserClient(WebClient http, String organization) {
        this.http = http;
        this.organization = organization;
    }

    public boolean enabled() { return http != null; }

    /**
     * Change the caller's OWN Casdoor password. {@code username} MUST be the caller's
     * Casdoor USERNAME derived from the validated JWT by the caller (the
     * {@code preferred_username} claim — NEVER the JWT {@code sub}, which in this
     * platform is the Casdoor UUID on a real Casdoor JWT and the composite
     * {@code provider:handle} account id on a bff_-session synthetic principal, and
     * never a request field) — so a user can only change their own credential.
     * Casdoor additionally verifies {@code oldPassword} server-side even for
     * admin-credential callers (live-verified), so a compromised BFF credential
     * alone cannot rotate a password without the current one.
     *
     * <p>ERRORS PROPAGATE: Casdoor answers HTTP 200 with {@code {"status":"error",
     * "msg":...}} on a refused change (wrong oldPassword, unknown user, policy).
     * That is surfaced as a 400 {@link ApiException} carrying Casdoor's message —
     * never swallowed into a success acknowledgement (the pre-fix behaviour logged a
     * warning and completed OK, so the UI reported success while the password never
     * changed).
     */
    public Mono<Void> changePassword(String username, String oldPassword, String newPassword) {
        if (http == null) {
            log.info("[casdoor-user] (stub) password change for {}/{} — wired but Casdoor write disabled "
                    + "(casdoor.account.enabled=false)", organization, username);
            return Mono.empty();
        }
        // Casdoor reads set-password ONLY from the urlencoded form (a JSON body of
        // the same fields is rejected — live-verified), so this MUST stay fromFormData.
        return http.post()
                .uri("/api/set-password")
                .body(BodyInserters.fromFormData(form(Map.of(
                        "userOwner", organization,
                        "userName", username,
                        "oldPassword", oldPassword == null ? "" : oldPassword,
                        "newPassword", newPassword == null ? "" : newPassword))))
                .retrieve()
                .bodyToMono(Map.class)
                .flatMap(r -> requireOk("set-password", username, r))
                .then();
    }

    /**
     * Change the caller's OWN Casdoor email. {@code username} MUST be the caller's
     * Casdoor username derived from the JWT's {@code preferred_username} claim (see
     * {@link #changePassword}). The production path sends a verification code
     * first; here the live-confirmed update-user shape is issued:
     * {@code columns=email} scopes the write to the email column ONLY, which is
     * what makes the partial {@code {owner,name,email}} body valid (without it
     * Casdoor full-object-validates and rejects — live-verified) and guarantees
     * no other user field is touched.
     */
    public Mono<Void> changeEmail(String username, String newEmail) {
        if (http == null) {
            log.info("[casdoor-user] (stub) email change for {}/{} -> {} — wired but Casdoor write disabled "
                    + "(casdoor.account.enabled=false)", organization, username, newEmail);
            return Mono.empty();
        }
        Map<String, Object> user = new LinkedHashMap<>();
        user.put("owner", organization);
        user.put("name", username);
        user.put("email", newEmail);
        return http.post()
                .uri(uri -> uri.path("/api/update-user")
                        .queryParam("id", organization + "/" + username)
                        .queryParam("columns", "email").build())
                .bodyValue(user)
                .retrieve()
                .bodyToMono(Map.class)
                .flatMap(r -> requireOk("update-user(email)", username, r))
                .then();
    }

    /** Casdoor's set-password expects form-encoding (live-verified); build the urlencoded body. */
    private static MultiValueMap<String, String> form(Map<String, String> fields) {
        LinkedMultiValueMap<String, String> mv = new LinkedMultiValueMap<>();
        fields.forEach(mv::add);
        return mv;
    }

    /**
     * Casdoor's REST surface answers HTTP 200 for REFUSED operations too, carrying
     * {@code {"status":"error","msg":...}} in the body — so the HTTP status alone is
     * meaningless and the body's {@code status} field is the real outcome. A non-ok
     * body becomes a 400 {@link ApiException} carrying Casdoor's own message (wrong
     * old password, unknown user, org policy), which the exception handler surfaces
     * to the caller. NEVER log-and-complete: that is exactly the "change password
     * reports success but nothing changed" defect this method exists to prevent.
     */
    private static Mono<Map<?, ?>> requireOk(String op, String subject, Map<?, ?> response) {
        if (response != null && "ok".equals(response.get("status"))) {
            return Mono.just(response);
        }
        Object msg = response == null ? null : response.get("msg");
        String detail = (msg == null || String.valueOf(msg).isBlank())
                ? "no error message from the IdP" : String.valueOf(msg);
        log.warn("[casdoor-user] {} for {} REFUSED by Casdoor: {}", op, subject, detail);
        return Mono.error(ApiException.badRequest("identity provider refused " + op + ": " + detail));
    }
}
