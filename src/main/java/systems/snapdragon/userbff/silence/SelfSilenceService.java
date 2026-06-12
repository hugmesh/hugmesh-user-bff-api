package systems.snapdragon.userbff.silence;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import systems.snapdragon.userbff.federation.FederationApiClient;
import systems.snapdragon.userbff.security.DomainRegistry;
import systems.snapdragon.userbff.web.ApiException;

import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * USER SELF-SILENCE — self-service visibility hide; structurally DISTINCT from a ban.
 *
 * <p><b>The distinctness contract (enforced by construction):</b> a self-silence
 * writes ZERO Casdoor roles, ZERO {@code access_suspension} rows, and ZERO
 * revocation keys. This service is deliberately NOT injected with ANY revocation /
 * Casdoor-role / suspension client — it is structurally incapable of revoking a
 * token or removing a role. Its only collaborators are the durable
 * {@code self_silence} row, the federation hide-profile seam, and the homeserver
 * visibility-hide seams (all DISCOVERY-only). Login/home is UNCHANGED: the row never
 * gates the user's OWN access — they keep their session and full use of the service
 * while invisible to others.
 *
 * <p>Three fail-CLOSED, NON-token-affecting hides fire on activate, un-fire on
 * cancel/expiry:
 * <ol>
 *   <li>federation profile -> public 404 (a SELF-hide separate from a ban override;
 *       the owner still sees their own profile);</li>
 *   <li>akkoma discoverable=false (visibility flag, NEVER suspend);</li>
 *   <li>tuwunel directory exclusion (admin-room bot, NEVER deactivate).</li>
 * </ol>
 * All three are GATED stub-seams ({@code self-silence.federation.enabled} /
 * {@code external.<platform>.enabled}, default OFF) and NEVER hard-fail: the row is
 * the source of truth and the scheduled wake re-tries the un-hides until they stick.
 */
@Service
public class SelfSilenceService {

    private static final Logger log = LoggerFactory.getLogger(SelfSilenceService.class);

    private final SelfSilenceRepository repo;
    private final FederationApiClient federation;
    private final Map<String, HomeserverHideClient> hidesByPlatform;
    /** GATE for the federation hide-profile leg (the user-scope endpoint ships later). */
    private final boolean federationHideEnabled;

    public SelfSilenceService(SelfSilenceRepository repo,
                              FederationApiClient federation,
                              List<HomeserverHideClient> hideClients,
                              @Value("${self-silence.federation.enabled:false}") boolean federationHideEnabled) {
        this.repo = repo;
        this.federation = federation;
        this.federationHideEnabled = federationHideEnabled;
        this.hidesByPlatform = new java.util.HashMap<>();
        for (HomeserverHideClient c : hideClients) this.hidesByPlatform.put(c.platform(), c);
    }

    /**
     * Activate (or re-activate) the owner's self-silence until {@code expiresAt}. The
     * durable row is written FIRST (source of truth), THEN the three hides fire
     * best-effort (never fail the call). {@code localpart} is the caller's homeserver
     * handle (JWT preferred_username) used for the homeserver hide seams.
     */
    /** Back-compat overload — stamps/operates on the platform {@code default} domain. */
    public Mono<SelfSilence> activate(String owner, String localpart, Instant expiresAt, String reason) {
        return activate(owner, localpart, expiresAt, reason, DomainRegistry.DEFAULT_DOMAIN);
    }

    public Mono<SelfSilence> activate(String owner, String localpart, Instant expiresAt, String reason,
                                      String domain) {
        requireOwner(owner);
        if (expiresAt == null || !expiresAt.isAfter(Instant.now())) {
            return Mono.error(ApiException.badRequest("expiresAt must be in the future"));
        }
        return repo.activate(owner, expiresAt, reason, domain)
                .flatMap(saved -> applyHides(localpart).thenReturn(saved))
                .doOnSuccess(s -> log.info("[self-silence] activated for {} until {}", owner, expiresAt));
    }

    /** The owner's current silence row (active or cleared) within their DOMAIN, or
     *  empty if none. {@code domain} is the caller's validated-issuer brand (or
     *  {@code null} for the SUPERADMIN cross-domain bypass). */
    public Mono<SelfSilence> status(String owner, String domain) {
        requireOwner(owner);
        return repo.find(owner, domain);
    }

    /** Back-compat overload — scopes to the platform {@code default} domain. */
    public Mono<SelfSilence> status(String owner) {
        return status(owner, DomainRegistry.DEFAULT_DOMAIN);
    }

    /**
     * Cancel the owner's active self-silence early: un-hide all three legs, THEN
     * stamp {@code cleared_at} (fail-safe ordering — un-hides first, clear last; a
     * failed un-hide leaves the row active so the scheduled wake retries, never a
     * silent permanent hide). Idempotent: a no-op clear returns a notFound so the UI
     * can distinguish "nothing active".
     */
    /** Back-compat overload — scopes to the platform {@code default} domain. */
    public Mono<Void> cancel(String owner, String localpart) {
        return cancel(owner, localpart, DomainRegistry.DEFAULT_DOMAIN);
    }

    public Mono<Void> cancel(String owner, String localpart, String domain) {
        requireOwner(owner);
        Mono<SelfSilence> activeRow = repo.find(owner, domain)
                .filter(s -> s.clearedAt() == null)
                .switchIfEmpty(Mono.error(ApiException.notFound("no active self-silence to cancel")));
        return activeRow.flatMap(s -> clearHides(localpart)
                .then(repo.clear(owner, domain))
                .flatMap(cleared -> cleared > 0
                        ? Mono.<Void>empty()
                        : Mono.error(ApiException.notFound("no active self-silence to cancel"))));
    }

    /**
     * EMAIL-MOD — request a moderator/admin reactivation (un-silence sooner than
     * {@code expiresAt}). Writes a {@code kind='self-silence-appeal'} moderation
     * request via federation-api (the row IS the queue mods watch; NOT SMTP). Never
     * touches {@code access_suspension}. The caller must currently be self-silenced.
     */
    /** Back-compat overload — scopes to the platform {@code default} domain. */
    public Mono<Map<String, Object>> requestEarlyReactivation(String owner, String reason) {
        return requestEarlyReactivation(owner, reason, DomainRegistry.DEFAULT_DOMAIN);
    }

    public Mono<Map<String, Object>> requestEarlyReactivation(String owner, String reason, String domain) {
        requireOwner(owner);
        return repo.find(owner, domain).flatMap(s -> {
            if (s == null || !s.active()) {
                return Mono.error(ApiException.badRequest("no active self-silence to request reactivation for"));
            }
            return federation.requestSelfSilenceReactivation(owner, reason)
                    .map(resp -> Map.of("requested", true, "transport", "moderation-request",
                            "kind", "self-silence-appeal", "federation", resp));
        }).switchIfEmpty(Mono.error(ApiException.badRequest("no active self-silence to request reactivation for")));
    }

    // ── hide / un-hide legs (all fail-CLOSED: never hard-fail the flow) ──────

    /** Fire all three hides best-effort; the row already stands so failures are logged, not thrown. */
    Mono<Void> applyHides(String localpart) {
        Mono<Void> fed = federationHideEnabled
                ? federation.applyHideProfile()
                    .onErrorResume(e -> { log.warn("[self-silence] federation hide-profile failed (row kept): {}", e.toString()); return Mono.empty(); })
                : Mono.fromRunnable(() -> log.info("[self-silence] (stub) federation hide-profile disabled (self-silence.federation.enabled=false)"));
        return fed
                .then(hidePlatform("mastodon", localpart, true))
                .then(hidePlatform("matrix", localpart, true))
                .then();
    }

    /** Reverse all three hides best-effort (used by cancel + the scheduled wake). */
    Mono<Void> clearHides(String localpart) {
        Mono<Void> fed = federationHideEnabled
                ? federation.clearHideProfile()
                    .onErrorResume(e -> { log.warn("[self-silence] federation un-hide failed: {}", e.toString()); return Mono.empty(); })
                : Mono.fromRunnable(() -> log.info("[self-silence] (stub) federation un-hide disabled (self-silence.federation.enabled=false)"));
        return fed
                .then(hidePlatform("mastodon", localpart, false))
                .then(hidePlatform("matrix", localpart, false))
                .then();
    }

    private Mono<Void> hidePlatform(String platform, String localpart, boolean hide) {
        HomeserverHideClient client = hidesByPlatform.get(platform);
        if (client == null || localpart == null || localpart.isBlank()) return Mono.empty();
        Mono<Boolean> call = hide ? client.hide(localpart) : client.unhide(localpart);
        return call.onErrorResume(e -> {
            log.warn("[self-silence] best-effort {} {}-hide for {} failed: {}",
                    platform, hide ? "" : "un", localpart, e.toString());
            return Mono.just(false);
        }).then();
    }

    private static void requireOwner(String owner) {
        if (owner == null || owner.isBlank()) {
            throw ApiException.unauthorized("missing authenticated subject");
        }
    }
}
