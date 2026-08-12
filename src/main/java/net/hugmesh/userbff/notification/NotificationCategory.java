package net.hugmesh.userbff.notification;

import java.util.List;

/**
 * The fixed vocabulary of notification categories the notifications subsystem speaks
 * — the single source of truth the prefs/inbox API + the 012 CHECK constraints both
 * enforce. A category the BFF doesn't recognise is rejected fail-closed (a 400),
 * mirroring the {@code MediaPoisonDecision} vocabulary helpers + the 005/007 CHECK
 * parity pattern.
 *
 * <ul>
 *   <li>{@link #ACCOUNT_RESTRICTION} — account-status changes (suspension/restriction
 *       lift). FORCED-ON (un-silenceable): the prefs API coerces enabled=false to
 *       true on this category and the 012-3 DB CHECK is the backstop, so a user can
 *       NEVER silence being told their account was restricted.</li>
 *   <li>{@link #ROLE_CHANGE} — the caller's roles were granted/revoked.</li>
 *   <li>{@link #INFRA_IMPACTING} — infra events that affect the caller (node/service
 *       outage, scheduled maintenance).</li>
 *   <li>{@link #FEATURE_AVAILABILITY} — a feature/optional-service became
 *       available/unavailable for the caller's brand.</li>
 * </ul>
 *
 * <p>Every category defaults to ENABLED (opt-out, not opt-in) so a user gets the
 * notifications by default until they explicitly silence a (silenceable) category.
 */
public final class NotificationCategory {

    private NotificationCategory() {}

    /** Account-status changes — FORCED-ON / un-silenceable. */
    public static final String ACCOUNT_RESTRICTION = "account-restriction";
    /** The caller's roles were granted/revoked. */
    public static final String ROLE_CHANGE = "role-change";
    /** Infra events affecting the caller (outage / maintenance). */
    public static final String INFRA_IMPACTING = "infra-impacting";
    /** A feature/optional-service became available/unavailable for the brand. */
    public static final String FEATURE_AVAILABILITY = "feature-availability";

    /** Every category, in a stable presentation order (drives the defaults view). */
    public static final List<String> ALL = List.of(
            ACCOUNT_RESTRICTION, ROLE_CHANGE, INFRA_IMPACTING, FEATURE_AVAILABILITY);

    /** True iff {@code category} is a notification category this BFF recognises
     *  (fail-closed on anything else). */
    public static boolean isValid(String category) {
        return ALL.contains(category);
    }

    /** True iff {@code category} is the FORCED-ON (un-silenceable) account-restriction
     *  category — the prefs API coerces enabled=false to true here. */
    public static boolean isForcedOn(String category) {
        return ACCOUNT_RESTRICTION.equals(category);
    }
}
