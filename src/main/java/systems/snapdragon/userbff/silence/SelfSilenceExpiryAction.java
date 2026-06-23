package systems.snapdragon.userbff.silence;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

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
    private final AtomicReference<Instant> lastSuccessAt = new AtomicReference<>();

    public SelfSilenceExpiryAction(SelfSilenceRepository repo, SelfSilenceService silence) {
        this.repo = repo;
        this.silence = silence;
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
        return isBanned(s.userId()).flatMap(banned -> {
            if (banned) {
                log.info("[self-silence] skipping wake for {} — active ban dominates (not un-hiding)", s.userId());
                return Mono.just(0L);
            }
            // localpart == user_id fallback on the scheduled path (no request JWT /
            // stored localpart); the homeserver un-hide seams are best-effort + gated.
            return silence.clearHides(s.userId())
                    // SYSTEM clear (unscoped): the expiry sweep auto-clears overdue
                    // silences across ALL brands — it is a platform task, not a
                    // per-principal mutation. See SelfSilenceRepository.clearSystem.
                    .then(repo.clearSystem(s.userId()))
                    .doOnSuccess(c -> { if (c > 0) log.info("[self-silence] auto-cleared expired silence for {}", s.userId()); });
        });
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
