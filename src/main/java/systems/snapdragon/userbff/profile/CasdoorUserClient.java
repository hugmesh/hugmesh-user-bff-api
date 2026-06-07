package systems.snapdragon.userbff.profile;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Reactive wrapper around the Casdoor IdP "change my own credentials" surface.
 * Password + email are owned by Casdoor (the identity provider), NOT by this BFF's
 * {@code user_profile} table, so a self-service password/email change must go to
 * Casdoor — the BFF never stores credentials.
 *
 * <p>Documented Casdoor endpoints (Casdoor admin/account API):
 * <ul>
 *   <li>password: {@code POST /api/set-password} with form fields
 *       {@code userOwner}, {@code userName}, {@code oldPassword}, {@code newPassword}.</li>
 *   <li>email: {@code POST /api/update-user?id=<org>/<name>} with the user object
 *       carrying the new {@code email} (Casdoor has no narrower "set-email" call;
 *       a verification flow via {@code /api/send-verification-code} +
 *       {@code /api/verify-code} is the production path).</li>
 * </ul>
 *
 * <p>STUB STATUS: the exact Casdoor payload + the per-user auth (the caller's own
 * Casdoor session vs. a service credential) is version-specific and uncertain, so
 * the actual HTTP call is GATED OFF by default (a configured {@link WebClient} is
 * only present when {@code casdoor.account.enabled=true}). When disabled the
 * reactive flow is still fully wired: the controller -> service -> this client
 * chain runs and returns a "queued" acknowledgement WITHOUT a live Casdoor write.
 * The reactive HTTP shape below is the real one to validate against a running
 * casdoor-all-in-one before flipping the flag on (see README deferrals).
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
     * Change the caller's OWN Casdoor password. {@code username} MUST be derived
     * from the JWT subject by the caller — never from a request field — so a user
     * can only change their own credential.
     */
    public Mono<Void> changePassword(String username, String oldPassword, String newPassword) {
        if (http == null) {
            log.info("[casdoor-user] (stub) password change for {}/{} — wired but Casdoor write disabled "
                    + "(casdoor.account.enabled=false)", organization, username);
            return Mono.empty();
        }
        return http.post()
                .uri("/api/set-password")
                .bodyValue(form(Map.of(
                        "userOwner", organization,
                        "userName", username,
                        "oldPassword", oldPassword == null ? "" : oldPassword,
                        "newPassword", newPassword == null ? "" : newPassword)))
                .retrieve()
                .bodyToMono(Map.class)
                .doOnNext(r -> warnIfNotOk("set-password", username, r))
                .then();
    }

    /**
     * Change the caller's OWN Casdoor email. {@code username} MUST be the JWT
     * subject's Casdoor username. The production path sends a verification code
     * first; here the documented update-user shape is issued.
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
                        .queryParam("id", organization + "/" + username).build())
                .bodyValue(user)
                .retrieve()
                .bodyToMono(Map.class)
                .doOnNext(r -> warnIfNotOk("update-user(email)", username, r))
                .then();
    }

    /** Casdoor's set-password expects form-encoding; build the body map. */
    private static Map<String, String> form(Map<String, String> fields) {
        return new LinkedHashMap<>(fields);
    }

    private static void warnIfNotOk(String op, String subject, Map<?, ?> response) {
        if (response != null && !"ok".equals(response.get("status"))) {
            log.warn("[casdoor-user] {} for {} returned non-ok: {}", op, subject, response);
        }
    }
}
