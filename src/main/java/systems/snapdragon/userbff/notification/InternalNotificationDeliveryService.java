package systems.snapdragon.userbff.notification;

import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import systems.snapdragon.commons.web.ApiException;

/**
 * The SYSTEM-side deliver path for the in-app notification FLOOR — the ONLY production
 * writer of {@code user_notifications}. Reached EXCLUSIVELY through the
 * service-principal internal endpoint ({@code POST /bff/user/internal/notifications},
 * gated to {@code ROLE_SERVICE} only); the snapdragon-actions reconciler is the caller.
 *
 * <p><b>Privilege boundary.</b> Unlike the user-facing read/prefs services (owner ==
 * JWT subject), this service takes the TARGET {@code (domain, userSubject)} EXPLICITLY
 * (the system delivers ON BEHALF OF a named user, not the caller). That is exactly why
 * the endpoint is unreachable by any human JWT: a human reaching it could write a
 * notification to ANY user (a spoofing IDOR). The service NEVER synthesises an actor
 * identity — {@code title}/{@code body} are taken verbatim from the request (the
 * reconciler builds them).
 *
 * <p><b>Suppression.</b> The per-category preference gates delivery: a SUPPRESSED
 * (enabled=false) category is NOT written and reports {@code delivered=false,
 * reason=suppressed}. The {@code account-restriction} category is FORCED-ON
 * (un-silenceable) — it is ALWAYS delivered regardless of any stored preference, so a
 * user can never silence being told their account was restricted.
 *
 * <p><b>Idempotency.</b> The row id is the DETERMINISTIC
 * {@link StableNotificationId#forInApp} of the source event, so the write is
 * INSERT-IF-ABSENT: a retried delivery of the same {@code (sourceTable, sourceId)} finds
 * the row already present and reports {@code delivered=true, deduped=true} WITHOUT
 * writing a second row.
 */
@Service
public class InternalNotificationDeliveryService {

    private final UserNotificationRepository notifications;
    private final NotificationPreferenceRepository preferences;

    public InternalNotificationDeliveryService(UserNotificationRepository notifications,
                                               NotificationPreferenceRepository preferences) {
        this.notifications = notifications;
        this.preferences = preferences;
    }

    /** The outcome of a deliver call (serialised to the endpoint's JSON body). */
    public record DeliveryResult(boolean delivered, boolean deduped, String reason) {
        static DeliveryResult inserted()    { return new DeliveryResult(true, false, null); }
        static DeliveryResult dedupedHit()  { return new DeliveryResult(true, true, null); }
        static DeliveryResult suppressedResult() { return new DeliveryResult(false, false, "suppressed"); }
    }

    /**
     * Deliver one in-app notification to the TARGET {@code (domain, userSubject)} (both
     * from the request body — the system acts on the user's behalf). Validates the
     * fixed-vocabulary {@code category} (fail-closed 400), honours the per-category
     * preference (account-restriction forced-on), and writes INSERT-IF-ABSENT under the
     * deterministic source-derived id.
     */
    public Mono<DeliveryResult> deliver(String domain, String userSubject, String category,
                                        String title, String body,
                                        String sourceTable, String sourceId) {
        String dom = trimmed(domain);
        String owner = trimmed(userSubject);
        String cat = trimmed(category);
        String ttl = title == null ? "" : title.trim();
        String srcTable = trimmed(sourceTable);
        String srcId = trimmed(sourceId);

        if (dom.isEmpty())   return badRequest("domain is required");
        if (owner.isEmpty()) return badRequest("userSubject is required");
        if (!NotificationCategory.isValid(cat)) return badRequest("unknown notification category");
        if (ttl.isEmpty())   return badRequest("title is required");
        if (srcTable.isEmpty()) return badRequest("sourceTable is required");
        if (srcId.isEmpty())    return badRequest("sourceId is required");

        String id = StableNotificationId.forInApp(srcTable, srcId);

        // FORCED-ON: account-restriction is always delivered, regardless of the stored
        // preference (un-silenceable). Every other category is suppressed when the
        // target has explicitly disabled it.
        Mono<Boolean> allowed = NotificationCategory.isForcedOn(cat)
                ? Mono.just(Boolean.TRUE)
                : preferences.isEnabled(owner, cat, dom);

        return allowed.flatMap(enabled -> {
            if (!Boolean.TRUE.equals(enabled)) {
                return Mono.just(DeliveryResult.suppressedResult());   // no write
            }
            return notifications.insertIfAbsent(id, dom, owner, cat, ttl, body)
                    .map(inserted -> inserted ? DeliveryResult.inserted() : DeliveryResult.dedupedHit());
        });
    }

    private static Mono<DeliveryResult> badRequest(String msg) {
        return Mono.error(ApiException.badRequest(msg));
    }

    private static String trimmed(String s) {
        return s == null ? "" : s.trim();
    }
}
