package systems.snapdragon.userbff.auth;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Mono;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The INTERNAL service-to-service client to snapdragon-admin-bff, which OWNS the
 * account + bff_session tables. user-bff has NO account/session database of its own
 * (mutual db-denial NetworkPolicy with admin-bff), so every account/session operation
 * the SSO-login relocation needs is DELEGATED here over HTTP to admin-bff's internal
 * surface ({@code /bff/internal/**}, guarded by admin-bff's auth-core
 * {@code InternalTokenWebFilter}).
 *
 * <p>It targets the admin-bff #112 internal contract + the custody-stamp endpoint.
 * Until #112 lands and its method shapes are pinned for the flag-flip, this client
 * SHIPS FAIL-CLOSED-STUBBED: when the OIDC surface is disabled
 * ({@code app.bff.oidc.enabled=false}) the {@link WebClient} is {@code null} and every
 * call returns {@code Mono.error(...)} — NEVER a silent success that could let an
 * un-provisioned caller through. This mirrors the gated-stub shape of
 * {@code client.RevocationWriter} (null client ⇒ documented stub) while differing in
 * its FAILURE posture: a revocation write is best-effort and converges next tick, but
 * an account/session op on the login path is security-critical, so its stub ERRORS
 * rather than no-ops.
 *
 * <p>Outbound calls carry the {@code X-Internal-Token} stamp (configured on the
 * {@link WebClient} in {@link AdminBffInternalConfig}) so they satisfy admin-bff's
 * inbound {@code InternalTokenWebFilter}, and present this BFF's cluster-CA client cert
 * when {@code snapdragon.mtls.client.enabled=true} (see {@link AdminBffInternalConfig}).
 */
public class AdminBffInternalClient {

    private static final Logger log = LoggerFactory.getLogger(AdminBffInternalClient.class);

    /** A provisioned account view (admin-bff is the source of truth). */
    public record AccountView(String id, String provider, String handle,
                              boolean registrationComplete, List<String> roles) {
        // Return a defensive copy so callers cannot mutate the internal list.
        @Override
        public List<String> roles() {
            return roles == null ? List.of() : List.copyOf(roles);
        }
    }

    /** A freshly-minted opaque {@code bff_} session token from admin-bff. */
    public record SessionView(String token, String accountId) {}

    /** The subset of admin-bff's {@code /bff/internal/session/introspect} body we need to
     *  resolve a session token to its account id (the rest — provider/roles/status/mfa — is
     *  re-read from the full account view, so unknown fields are ignored). */
    @JsonIgnoreProperties(ignoreUnknown = true)
    private record SessionIntrospect(String id) {}

    /** Null unless app.bff.oidc.enabled=true — when null every call is a fail-closed
     *  stub (Mono.error), so a disabled surface can never silently authenticate. */
    private final WebClient http;

    public AdminBffInternalClient(WebClient http) {
        this.http = http;
    }

    /** Whether the live admin-bff internal client is wired (vs. the fail-closed stub). */
    public boolean enabled() {
        return http != null;
    }

    /**
     * Ensure an account exists for {@code (provider, handle)} — admin-bff creates it on
     * first sight (account writes go through admin-bff's AccountStore / Casdoor mgmt API,
     * NEVER a direct casdoor-pg write) and returns the canonical view either way.
     */
    public Mono<AccountView> ensureAccount(String provider, String handle) {
        if (http == null) {
            return stub("ensureAccount");
        }
        return http.post().uri("/bff/internal/accounts/ensure")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(Map.of("provider", provider, "handle", handle))
                .retrieve()
                .bodyToMono(AccountView.class);
    }

    /** Fetch the account view by id (e.g. after resolving a session). */
    public Mono<AccountView> getAccount(String accountId) {
        if (http == null) {
            return stub("getAccount");
        }
        return http.get().uri("/bff/internal/accounts/{id}", accountId)
                .retrieve()
                .bodyToMono(AccountView.class);
    }

    /**
     * Resolve the account view from an opaque {@code bff_} SESSION token (the {@code /me} +
     * {@code /session} hydrate path). The session token is NOT an account id — it must be
     * introspected first: admin-bff's {@code GET /bff/internal/session/introspect} maps the
     * {@code Authorization: Bearer bff_<token>} to its owning account, and we then fetch that
     * account's full view (which carries {@code handle}, absent from the introspect body) by id.
     *
     * <p>This replaces the earlier {@code getAccount(sessionToken)} bug: a session token
     * ({@code bff_}+random) is never an account primary key ({@code provider:handle}), so
     * {@code GET /bff/internal/accounts/{bff_token}} always 404'd — every {@code /bff/me} and
     * {@code /bff/session} call failed (masked while the surface shipped dark). Fail-closed
     * stub when the OIDC surface is disabled, exactly like the other calls. Unknown/expired
     * session ⇒ admin-bff 401 (propagated), never a fabricated view.
     */
    public Mono<AccountView> getAccountBySession(String bffToken) {
        if (http == null) {
            return stub("getAccountBySession");
        }
        return http.get().uri("/bff/internal/session/introspect")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + bffToken)
                .retrieve()
                .bodyToMono(SessionIntrospect.class)
                .flatMap(intro -> getAccount(intro.id()))
                // An unknown/expired (or non-bff) session ⇒ admin-bff introspect 401. Surface it
                // to the caller AS a 401 so the /me + /session hydrate path returns "no session"
                // (the login-ui then re-logs-in) instead of a bare 500 from the raw
                // WebClientResponseException. The dark stub path (IllegalStateException) is
                // unaffected — it stays fail-closed.
                .onErrorMap(WebClientResponseException.Unauthorized.class,
                        e -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "unknown or expired session"));
    }

    /** Mark the account's registration as complete (the post-profile step). */
    public Mono<AccountView> completeAccount(String accountId) {
        if (http == null) {
            return stub("completeAccount");
        }
        return http.post().uri("/bff/internal/accounts/{id}/complete", accountId)
                .retrieve()
                .bodyToMono(AccountView.class);
    }

    /**
     * Whether {@code (provider, handle)} is allowed to register/log in (admin-bff owns
     * the allowlist). Fail-closed: the stub errors rather than returning {@code true}.
     */
    public Mono<Boolean> allowlistCheck(String provider, String handle) {
        if (http == null) {
            return stub("allowlistCheck");
        }
        return http.get().uri("/bff/internal/allowlist/{provider}/{handle}", provider, handle)
                .retrieve()
                .bodyToMono(Boolean.class);
    }

    /** Mint a fresh opaque {@code bff_} session for the account; admin-bff persists the
     *  bff_session row (user-bff never writes that DB). */
    public Mono<SessionView> createSession(String accountId) {
        if (http == null) {
            return stub("createSession");
        }
        return http.post().uri("/bff/internal/sessions")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(Map.of("accountId", accountId))
                .retrieve()
                .bodyToMono(SessionView.class);
    }

    /** Revoke (delete) a session by its opaque token — the {@code /sessionOut} leg. */
    public Mono<Void> deleteSession(String token) {
        if (http == null) {
            return stub("deleteSession");
        }
        return http.delete().uri("/bff/internal/sessions/{token}", token)
                .retrieve()
                .toBodilessEntity()
                .then();
    }

    /** The account's namespace grants (the {@code /me/namespaces} leg). */
    public Mono<List<NamespaceView>> accountNamespaces(String accountId) {
        if (http == null) {
            return stub("accountNamespaces");
        }
        return http.get().uri("/bff/internal/accounts/{id}/namespaces", accountId)
                .retrieve()
                .bodyToFlux(NamespaceView.class)
                .collectList();
    }

    /** A namespace grant view. */
    public record NamespaceView(String grantee, String namespace) {}

    /**
     * Stamp the encrypted OIDC custody blobs onto admin-bff's bff_session row. The
     * access/refresh tokens are AES-256-GCM-encrypted by {@link
     * systems.snapdragon.authcore.casdoor.BffCustodyCipher} on THIS side BEFORE the
     * call, so only opaque ciphertext crosses the wire and lands in admin-bff's
     * columns — user-bff never writes that DB, and a plaintext token is never stored
     * (the boot guard refuses {@code oidc.enabled} with a blank custody key).
     */
    public Mono<Void> stampCustody(String sessionToken, String encAccess, String encRefresh,
                                   long expiresInSeconds) {
        if (http == null) {
            return stub("stampCustody");
        }
        // encRefresh is nullable (Casdoor may return no refresh_token), so a null-tolerant
        // map is required — Map.of throws NPE on a null value. A LinkedHashMap keeps a
        // null encRefresh as an explicit JSON null, matching admin-bff's nullable column.
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("sessionToken", sessionToken);
        body.put("encAccess", encAccess);
        body.put("encRefresh", encRefresh);
        body.put("expiresInSeconds", expiresInSeconds);
        return http.post().uri("/bff/internal/custody/stamp")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(body)
                .retrieve()
                .toBodilessEntity()
                .then();
    }

    /**
     * The documented fail-closed stub: the OIDC surface is disabled (or admin-bff is
     * unreachable), so the call is rejected rather than silently succeeding. Logs at
     * debug (no token/PII) and errors with an {@link IllegalStateException}.
     */
    private <T> Mono<T> stub(String op) {
        log.debug("[admin-bff-internal] (stub) '{}' refused — internal client disabled "
                + "(app.bff.oidc.enabled=false); fail-closed, no account/session op performed", op);
        return Mono.error(new IllegalStateException(
                "admin-bff internal client disabled (app.bff.oidc.enabled=false): " + op));
    }
}
