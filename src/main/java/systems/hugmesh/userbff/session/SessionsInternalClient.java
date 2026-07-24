package systems.hugmesh.userbff.session;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.LocalDateTime;

/**
 * The INTERNAL service-to-service client to hugmesh-admin-bff for the user-facing
 * "active session management" reads/writes. admin-bff OWNS the {@code bff_session} table
 * (the opaque {@code bff_} session model — band 006 + the band-150/180 columns); user-bff
 * has NO session database of its own (mutual db-denial NetworkPolicy with admin-bff), so
 * the "list / revoke MY sessions" feature is DELEGATED here over HTTP to admin-bff's
 * internal surface ({@code /bff/internal/sessions/**}, guarded by admin-bff's auth-core
 * {@code InternalTokenWebFilter} — mTLS + constant-time {@code X-Internal-Token}).
 *
 * <p>This deliberately MIRRORS the established outbound posture of
 * {@link systems.hugmesh.userbff.auth.AdminBffInternalClient} +
 * {@link systems.hugmesh.userbff.auth.AdminBffInternalConfig} (the mTLS connector of
 * {@code FederationHttpClientSsl} + the outbound {@code X-Internal-Token} default header),
 * but it is a SEPARATE bean with its OWN lifecycle: the {@code AdminBffInternalClient} is
 * gated behind the dark OIDC-login flag ({@code app.bff.oidc.enabled=false} ⇒ fail-closed
 * stub), whereas session management is an ALWAYS-ON user feature that must work in the live
 * gateway-forwarded-JWT world today. So this client is wired independently and degrades
 * gracefully (graceful-empty list / graceful no-op revoke) rather than coupling to the OIDC
 * kill-switch.
 *
 * <p>SECURITY: the {@code accountId} passed to {@link #sessionsForAccount(String)} MUST be
 * derived SERVER-SIDE from the validated JWT principal by the caller (see
 * {@link SessionsService}) — NEVER from a request parameter — so a user can only ever list
 * THEIR OWN sessions.
 *
 * <p>NOTE (companion admin-bff change): the {@code DELETE /bff/internal/sessions/{token}}
 * leg already exists on admin-bff's {@code InternalAccountController}. The
 * {@code GET /bff/internal/sessions/{accountId}} list leg consumed here is the companion
 * endpoint admin-bff exposes from {@code AccountStore.sessionsForAccount(accountId)}
 * (which projects to auth-core's {@code BffSessionRow}); it ships in a paired admin-bff PR.
 * The wire shape {@link BffSessionWire} mirrors that {@code BffSessionRow} field-for-field.
 */
public class SessionsInternalClient {

    private static final Logger log = LoggerFactory.getLogger(SessionsInternalClient.class);

    /**
     * The wire shape admin-bff returns for one {@code bff_session} row — mirrors auth-core's
     * {@code systems.hugmesh.authcore.account.BffSessionRow} field-for-field (the
     * lifecycle-identity columns ONLY; never the encrypted custody/MFA internals). The raw
     * {@code token} IS a live credential, so {@link SessionsService} maps it to an opaque id
     * before anything reaches a browser.
     */
    public record BffSessionWire(String token, String accountId,
                                 LocalDateTime createdAt, LocalDateTime expiresAt) {
    }

    /** Null unless the live internal client is wired — when null every call degrades to a
     *  graceful empty/no-op (the user-facing list-my-sessions feature is non-destructive,
     *  so an unreachable/disabled admin-bff yields an empty list, never a 500). */
    private final WebClient http;

    public SessionsInternalClient(WebClient http) {
        this.http = http;
    }

    /** Whether the live admin-bff session client is wired (vs. the graceful-empty stub). */
    public boolean enabled() {
        return http != null;
    }

    /**
     * List the NON-EXPIRED opaque sessions for {@code accountId} (admin-bff filters expired
     * rows at the DB and returns them newest-first). The {@code accountId} is server-derived
     * from the validated principal by the caller — NEVER a request param.
     *
     * <p>When the client is unwired (null) the read yields an empty stream rather than an
     * error: a non-destructive "list my sessions" read must degrade gracefully.
     */
    public Flux<BffSessionWire> sessionsForAccount(String accountId) {
        if (http == null) {
            log.debug("[admin-bff-sessions] (stub) sessionsForAccount degraded to empty — internal client unwired");
            return Flux.empty();
        }
        return http.get().uri("/bff/internal/sessions/{accountId}", accountId)
                .retrieve()
                .bodyToFlux(BffSessionWire.class);
    }

    /**
     * Revoke (delete) one opaque {@code bff_} session by its raw token — admin-bff's
     * idempotent {@code DELETE /bff/internal/sessions/{token}} (always 204). The caller
     * ({@link SessionsService}) has ALREADY verified the target session belongs to the
     * caller before this is invoked.
     *
     * <p>When the client is unwired (null) the revoke is a no-op completion rather than an
     * error (the feature is gracefully degraded when admin-bff is unreachable/disabled).
     */
    public Mono<Void> deleteSession(String token) {
        if (http == null) {
            log.debug("[admin-bff-sessions] (stub) deleteSession degraded to no-op — internal client unwired");
            return Mono.empty();
        }
        return http.delete().uri("/bff/internal/sessions/{token}", token)
                .retrieve()
                .toBodilessEntity()
                .then();
    }
}
