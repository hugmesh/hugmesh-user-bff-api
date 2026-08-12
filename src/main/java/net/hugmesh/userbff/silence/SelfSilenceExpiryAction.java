package net.hugmesh.userbff.silence;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;
import reactor.util.function.Tuple2;
import reactor.util.function.Tuples;
import net.hugmesh.userbff.auth.AdminBffInternalClient;

import java.time.Instant;
import java.util.concurrent.atomic.AtomicReference;

/**
 * SCHEDULED WAKE for self-silence — auto-clears every silence at its {@code expires_at}
 * so the user becomes visible again WITHOUT any manual action. {@code expires_at} is
 * authoritative and the row is the source of truth, so this re-selects ALL overdue-
 * but-uncleared rows on every tick (including the FIRST tick after a restart — a
 * pending wake is never lost across a reboot).
 *
 * <p>Per overdue row: un-hide all legs FIRST (federation profile re-shows; homeserver
 * directory re-includes), THEN stamp {@code cleared_at} — fail-safe ordering, so a
 * failed un-hide leaves the row active and it retries next tick (never a silent
 * permanent hide). Mirrors the {@code GitHubOrgAdminReconcileAction} @Scheduled shape.
 *
 * <p>BAN DOMINATES: a self-silence wake must never resurrect a BANNED user's
 * visibility. The authoritative ban store ({@code access_suspension}) lives in
 * admin-bff (a different service/DB) — this BFF has no such table — so the check is a
 * documented gated SEAM ({@link #isBanned}, default "not banned"); when admin-bff
 * exposes a suspension lookup it is wired here. The user-side homeserver un-hide is
 * itself best-effort + gated, and a ban's own homeserver deactivation dominates a
 * discovery flag, so a not-yet-wired seam cannot un-ban anyone.
 *
 * <p>This action lives in user-bff and NEVER writes a Casdoor role / suspension /
 * revocation — the self-silence distinctness invariant holds in the wake path too.
 * Exposes {@link #lastSuccessAt()} (a poll-able gauge) for monitoring.
 */
@Component
public class SelfSilenceExpiryAction {

    private static final Logger log = LoggerFactory.getLogger(SelfSilenceExpiryAction.class);

    private final SelfSilenceRepository repo;
    private final SelfSilenceService silence;
    private final AdminBffInternalClient adminBff;
    private final AtomicReference<Instant> lastSuccessAt = new AtomicReference<>();

    public SelfSilenceExpiryAction(SelfSilenceRepository repo, SelfSilenceService silence,
                                   AdminBffInternalClient adminBff) {
        this.repo = repo;
        this.silence = silence;
        this.adminBff = adminBff;
    }

    /**
     * Re-select overdue-active silences and auto-clear each. Default cadence 60s with
     * a 30s initial delay (overridable via {@code self-silence.check-interval-ms} /
     * {@code self-silence.initial-delay-ms}), matching the reconcile-action template.
     */
    @Scheduled(
            fixedDelayString = "${self-silence.check-interval-ms:60000}",
            initialDelayString = "${self-silence.initial-delay-ms:30000}")
    public void runOnce() {
        sweep().subscribe(
                n -> { if (n > 0) log.info("[self-silence] expiry sweep cleared {} silence(s)", n); },
                e -> log.warn("[self-silence] expiry sweep failed: {}", e.toString()));
    }

    /**
     * The reactive sweep (separated for testability): clears each overdue-active row
     * (un-hide first, stamp last; skip banned), returning the count cleared. Stamps
     * {@link #lastSuccessAt()} on completion.
     */
    Mono<Long> sweep() {
        Instant now = Instant.now();
        return repo.findOverdueActive(now)
                .concatMap(this::wake)
                .reduce(0L, Long::sum)
                .doOnSuccess(n -> lastSuccessAt.set(Instant.now()));
    }

    /** Un-hide + clear one overdue silence (or skip it if the user is banned). Returns 1 if cleared, else 0. */
    private Mono<Long> wake(SelfSilence s) {
        // Check ban dominance before un-hiding; a banned user's silence must not be lifted.
        return isBanned(s.userId()).flatMap(banned -> performWake(banned, s.userId()));
    }

    /** Skip the wake if the user is actively banned; otherwise un-hide all legs then stamp cleared_at. */
    private Mono<Long> performWake(boolean banned, String userId) {
        if (banned) {
            log.info("[self-silence] skipping wake for {} — active ban dominates (not un-hiding)", userId);
            return Mono.just(0L);
        }
        return resolveWakeLocalparts(userId)
                .flatMap(lp -> silence.clearHides(lp.getT1(), lp.getT2()))
                // SYSTEM clear (unscoped): the expiry sweep auto-clears overdue
                // silences across ALL brands — it is a platform task, not a
                // per-principal mutation. See SelfSilenceRepository.clearSystem.
                .then(repo.clearSystem(userId))
                .doOnSuccess(c -> { if (c > 0) log.info("[self-silence] auto-cleared expired silence for {}", userId); });
    }

    /**
     * Resolve the (matrixLocalpart, mastodonLocalpart) pair to un-hide this row under, via
     * a real admin-bff account read keyed by the row's stored {@code user_id}. This agrees
     * with the SAME canonical value {@code SelfSilenceController} resolved at activate-time
     * for a native-login / {@code bff_}-session row, because {@code
     * BffSessionAuthenticationWebFilter.syntheticJwt} stamps {@code .subject(view.id())} —
     * i.e. the stored {@code user_id} IS the admin-bff account id for that path.
     *
     * <p>FALLBACK (last resort, not the primary path): on ANY resolution failure — the
     * account 404s, admin-bff is unreachable, or a resolved field is blank — that
     * platform's leg falls back to the raw {@code user_id}, the pre-fix behaviour. This is
     * the ONLY reachable case for a self-silence row created via a real, externally-issued
     * Casdoor JWT presented directly to {@code /bff/user/self-silence/**} ({@code
     * SecurityConfig} still wires that route's {@code o.jwt(...)} resource server, so such
     * a token reaches it without ever passing through {@code
     * BffSessionAuthenticationWebFilter}): there {@code user_id} is Casdoor's raw subject,
     * not an admin-bff account id, so the lookup here 404s and this degrades to exactly
     * today's un-hide target. Never breaks the sweep's completion — mirrors this file's
     * existing "never hard-fail" style.
     */
    private Mono<Tuple2<String, String>> resolveWakeLocalparts(String userId) {
        return adminBff.getAccount(userId)
                .map(a -> Tuples.of(orFallback(a.localpart(), userId), orFallback(a.mastodonLocalpart(), userId)))
                .onErrorResume(e -> Mono.just(Tuples.of(userId, userId)));
    }

    /** {@code canonical} when resolved (non-blank); else the last-resort {@code userId}. */
    private static String orFallback(String canonical, String userId) {
        return (canonical == null || canonical.isBlank()) ? userId : canonical;
    }

    /**
     * BAN-DOMINANCE seam — does the user have an active ban that must NOT be un-hidden?
     * Authoritative {@code access_suspension} lives in admin-bff; until a lookup is
     * wired this defaults to {@code false} (not banned). Kept as a method so the wire-
     * up is a single, audited change.
     */
    private Mono<Boolean> isBanned(String ignored) {
        return Mono.just(false);
    }

    /** Last successful sweep completion — a poll-able liveness gauge for monitoring. */
    public Instant lastSuccessAt() {
        return lastSuccessAt.get();
    }
}
