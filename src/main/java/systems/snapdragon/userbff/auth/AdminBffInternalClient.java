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

    /**
     * A provisioned account view (admin-bff is the source of truth).
     *
     * <p>{@code localpart} is the CANONICAL, collision-checked homeserver (Matrix/Mastodon)
     * username admin-bff persisted at registration/{@code ensureAccount} time (Liquibase
     * changeset 290, {@code account.localpart} — the account-takeover-by-collision fix).
     * Matrix/Mastodon-proxy callers MUST use this instead of deriving a candidate from a
     * Casdoor JWT claim ({@code preferred_username}/{@code sub}): two DIFFERENT accounts can
     * share the same JWT-claim-derived candidate (that is the exact bug this closes), but
     * admin-bff guarantees {@code localpart} is unique across every account it holds. May be
     * blank for a row that predates the column. A blank value here is expected to be
     * RARE/transient, not "absent forever": admin-bff self-heals it (still through the same
     * collision-checked resolver) the next time this account is read via a path that needs it
     * (e.g. {@code AuthController#provision}).
     *
     * <p>{@code mastodonLocalpart} (admin-bff Liquibase changeset 291) is the coarser
     * Mastodon/Akkoma fold ({@code [a-z0-9_]}, 30-cap) of {@code localpart}, with its OWN
     * UNIQUE constraint. The Mastodon-mint call sites ({@code MastodonProxyController}, the
     * media leg) read THIS field, not a client-side re-fold of {@code localpart}: two accounts
     * DISTINCT under the Matrix fold ({@code john.doe} vs {@code john-doe}) still collapse to
     * one Mastodon localpart, and the shared-service-password recover leg would let the second
     * take over the first — exactly the residual takeover 291 closes. {@code
     * @JsonIgnoreProperties(ignoreUnknown = true)} is added so a NEWER admin-bff that emits a
     * further account field can never break this consumer's parse (cross-repo deploy skew).
     *
     * <p>{@code issuer} (admin-bff Liquibase changeset 301) is the account's OWN Casdoor
     * issuer URI — the BRAND discriminator (the platform runs one Casdoor per brand), a
     * different axis entirely from {@code provider}, which is only the OAuth LOGIN provider
     * (google/discord/casdoor). It closes the multi-brand blocker documented on {@code
     * BffSessionAuthenticationWebFilter#singleTrustedIssuerOrNull}: without a brand-aware
     * field, a {@code bff_} session on a genuinely multi-issuer cluster could not resolve its
     * brand at all and every domain-scoped read/write failed closed.
     *
     * <p><b>NOTE it does NOT arrive on this record's own wire.</b> This view is deserialised
     * from {@code GET /bff/internal/accounts/{id}} ({@code AccountOut}), which carries no
     * issuer; the issuer lives on the SESSION-introspect body. {@link #resolveSession} folds
     * it in via {@link #withIssuer} — so it is populated on the session-auth path and blank
     * everywhere else (a plain {@link #getAccount} view legitimately has none). Blank is
     * ALWAYS a safe value: consumers must re-validate it against their own trusted set and
     * degrade to the pre-301 fail-closed behavior. Never trust it without that check.
     */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record AccountView(String id, String provider, String handle,
                              boolean registrationComplete, List<String> roles,
                              String localpart, String mastodonLocalpart, String issuer) {

        /**
         * Copy {@code roles} on the way IN. The {@link #roles()} accessor already copies on
         * the way OUT, but that alone leaves the FIELD aliased to the caller's list — a
         * caller that keeps its reference can still mutate this view's roles after it is
         * built, which for a ROLE carrier is an authorization-relevant leak. Null is
         * preserved (the accessor maps it to an empty list) so the wire shape is unchanged.
         */
        public AccountView {
            roles = roles == null ? null : List.copyOf(roles);
        }

        /**
         * Back-compat constructor for callers/tests that predate the brand/issuer field
         * (admin-bff changeset 301): {@code issuer} defaults blank ("no brand known" — the
         * pre-301 shape, which makes the consumer fall back to {@code
         * singleTrustedIssuerOrNull}). Jackson deserialises admin-bff's {@code AccountOut}
         * JSON via the CANONICAL (8-arg) record constructor + component names — this extra
         * constructor is invisible to it, so the wire contract is unchanged.
         */
        public AccountView(String id, String provider, String handle, boolean registrationComplete,
                           List<String> roles, String localpart, String mastodonLocalpart) {
            this(id, provider, handle, registrationComplete, roles, localpart, mastodonLocalpart, "");
        }

        /**
         * Back-compat constructor for callers/tests that predate the Mastodon fold (changeset
         * 291): {@code mastodonLocalpart} defaults blank ("resolve it, never re-fold").
         */
        public AccountView(String id, String provider, String handle, boolean registrationComplete,
                           List<String> roles, String localpart) {
            this(id, provider, handle, registrationComplete, roles, localpart, "", "");
        }

        /**
         * Return a copy carrying {@code issuer} — the fold-in {@link #resolveSession} performs,
         * since the brand arrives on the session-introspect body while this view is hydrated
         * from the account-read endpoint. A null/blank issuer yields a blank field (the
         * pre-301 fail-closed shape), never null.
         */
        public AccountView withIssuer(String issuer) {
            return new AccountView(id, provider, handle, registrationComplete, roles,
                    localpart, mastodonLocalpart, issuer == null ? "" : issuer);
        }

        // Return a defensive copy so callers cannot mutate the internal list.
        @Override
        public List<String> roles() {
            return roles == null ? List.of() : List.copyOf(roles);
        }

        /** Never null — admin-bff's JSON always carries the field, but default defensively
         *  (blank, not the identity's raw handle) so a caller that forgets to check for
         *  blank never silently falls back to a JWT-claim-derived, un-collision-checked value. */
        @Override
        public String localpart() {
            return localpart == null ? "" : localpart;
        }

        /** Never null — the persisted Mastodon fold (changeset 291); blank means "not resolved
         *  yet" (an older admin-bff that does not emit it, or a pre-291 row), the same
         *  "resolve it, never re-fold" contract as {@link #localpart()}. */
        public String mastodonLocalpart() {
            return mastodonLocalpart == null ? "" : mastodonLocalpart;
        }

        /** Never null — the account's validated Casdoor issuer (the BRAND; admin-bff changeset
         *  301), folded in by {@link #resolveSession} from the session-introspect body. Blank
         *  means "no brand known": a legacy/off-path account row, an older admin-bff that does
         *  not emit the field, an issuer admin-bff did not trust, or simply a view obtained
         *  outside the session path. Blank MUST degrade to the pre-301 {@code
         *  singleTrustedIssuerOrNull} behavior — and a non-blank value is still only a HINT
         *  that the consumer re-validates against its own trusted set before use. */
        public String issuer() {
            return issuer == null ? "" : issuer;
        }
    }

    /** A freshly-minted opaque {@code bff_} session token from admin-bff. */
    public record SessionView(String token, String accountId) {}

    /** The fields of admin-bff's {@code GET /bff/internal/session/introspect} body this
     *  client consumes. {@code id} resolves the account (then re-fetched in full for its
     *  {@code handle}, absent here); {@code status} + {@code mfaSatisfied} are live,
     *  session-scoped facts that the account view does NOT carry — kept so the session
     *  bridge can deny a suspended/banned session and grant {@code MFA_SATISFIED} (see
     *  {@link #resolveSession}). Unknown fields ignored; {@code null} status defaults to
     *  {@code "active"} so a partial row never NPEs the mapping. */
    @JsonIgnoreProperties(ignoreUnknown = true)
    private record SessionIntrospect(String id, String status, boolean mfaSatisfied, String issuer) {
        SessionIntrospect {
            if (status == null) status = "active";
            // Changeset 301: the account's brand. NULLABLE on the wire by design — an older
            // admin-bff omits it entirely, and a current one emits null for a legacy/off-path
            // row or an issuer it did not trust. Normalise to blank so the fold-in and the
            // downstream trusted-set check never see null; blank == "no brand known" == the
            // pre-301 fail-closed shape.
            if (issuer == null) issuer = "";
        }
    }

    /** A resolved {@code bff_} session: the owning account view PLUS the two live,
     *  session-scoped facts the introspect body carries that {@link AccountView} does not
     *  ({@code status} — active/suspended/banned, live-checked server-side; {@code
     *  mfaSatisfied} — this session's MFA step-up state). Returned by {@link
     *  #resolveSession} for the session-auth bridge; the plain {@link #getAccountBySession}
     *  drops these for the {@code /bff/me} hydrate path that doesn't need them. */
    public record SessionResolution(AccountView account, String status, boolean mfaSatisfied) {}

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
        return resolveSession(bffToken).map(SessionResolution::account);
    }

    /**
     * Resolve a {@code bff_} SESSION token to its account view AND the two live,
     * session-scoped facts ({@code status}, {@code mfaSatisfied}) the introspect body
     * carries but {@link AccountView} does not — for the session-auth bridge, which must
     * deny a suspended/banned session and grant {@code MFA_SATISFIED}. Same two-hop shape
     * {@link #getAccountBySession} always used (introspect resolves token → account id +
     * status/mfa; {@code getAccount(id)} then fetches the full view for its {@code handle},
     * absent from the introspect body), just no longer discarding status/mfa on the way.
     *
     * <p>Unknown/expired (or non-bff) session ⇒ admin-bff introspect 401, surfaced AS a
     * 401 {@link ResponseStatusException} (so the caller returns "no session" instead of a
     * bare 500 from the raw {@link WebClientResponseException}). Fail-closed stub when the
     * OIDC surface is disabled, exactly like the other calls.
     */
    public Mono<SessionResolution> resolveSession(String bffToken) {
        if (http == null) {
            return stub("resolveSession");
        }
        return http.get().uri("/bff/internal/session/introspect")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + bffToken)
                .retrieve()
                .bodyToMono(SessionIntrospect.class)
                // Changeset 301: fold the account's brand (issuer) from the INTROSPECT body into
                // the account view — getAccount() reads /bff/internal/accounts/{id}, whose
                // AccountOut carries no issuer, so this is the only place the two halves meet.
                // Absent/blank (older admin-bff, legacy row, untrusted issuer) stays blank and
                // the synthetic-Jwt filter degrades to its pre-301 single-issuer fallback.
                .flatMap(intro -> getAccount(intro.id())
                        .map(account -> new SessionResolution(
                                account.withIssuer(intro.issuer()), intro.status(), intro.mfaSatisfied())))
                .onErrorMap(WebClientResponseException.Unauthorized.class,
                        e -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "unknown or expired session"));
    }

    /**
     * Swap an opaque {@code bff_} SESSION token for the INTERNAL custody Casdoor JWT
     * (admin-bff {@code POST /bff/internal/session/exchange}, body {@code {"token": …}},
     * response {@code {"bearer": <jwt>}}). This is the SAME back-channel the gateway's own
     * {@code BffJwtExchangeWebFilter} uses; user-bff calls it to obtain a REAL, forwardable
     * bearer for a native-login caller, whose SecurityContext principal is the SYNTHETIC
     * (non-forwardable) Jwt {@code BffSessionAuthenticationWebFilter} builds — so the
     * downstream federation-api / homeserver-proxy legs authenticate as the actual user
     * instead of going out credential-less (which federation-api rejects 401).
     *
     * <p>admin-bff's exchange endpoint carries a fail-closed suspension gate (a
     * suspended/banned session's swap is refused 403), so this never mints a usable bearer
     * for a curtailed account. The returned JWT is a live bearer credential and must only
     * be forwarded to a trusted in-mesh service over the same mTLS transport, never handed
     * to the browser.
     *
     * <p>Fail-closed stub when the OIDC surface is disabled. Any non-2xx (unknown/expired
     * session 404, suspended 403, custody disabled 503) propagates as the raw error so the
     * caller can decide NOT to forward (the forwarding filter treats any failure as "send
     * no bearer" — fail-closed downstream).
     */
    public Mono<String> exchangeSession(String bffToken) {
        if (http == null) {
            return stub("exchangeSession");
        }
        return http.post().uri("/bff/internal/session/exchange")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(Map.of("token", bffToken))
                .retrieve()
                .bodyToMono(EXCHANGE_RESPONSE_TYPE)
                .flatMap(body -> {
                    String bearer = body == null ? null : body.get("bearer");
                    return (bearer == null || bearer.isBlank())
                            ? Mono.error(new IllegalStateException("exchange returned no bearer"))
                            : Mono.just(bearer);
                });
    }

    private static final org.springframework.core.ParameterizedTypeReference<Map<String, String>>
            EXCHANGE_RESPONSE_TYPE = new org.springframework.core.ParameterizedTypeReference<>() {};

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
