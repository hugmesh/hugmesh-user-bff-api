package net.hugmesh.userbff.auth;

/**
 * The single allow-list for an introspected {@code bff_} session's account status. Both the
 * session-authentication filter (which grants authorities) and the {@code /bff/me} /
 * {@code /bff/session} view (which returns the account id, handle and roles) classify through
 * this one method, so the two cannot disagree about which statuses are usable.
 *
 * <p>Only an explicit {@code active} is usable. {@code suspended} and {@code banned} keep their
 * own reasons; anything else (missing, blank, padded, a value this service does not know, or a
 * non-ASCII lookalike) is {@link Verdict#UNRECOGNIZED} and refused. Comparison is ASCII-only:
 * {@link String#equalsIgnoreCase} folds {@code U+0130} (dotted capital I) to {@code i}, which
 * would accept "act" + U+0130 + "ve" as {@code active}.
 */
public final class SessionStatusPolicy {

    /** Classification of a session status. {@link #reason()} is a constant, never the raw
     *  backend-supplied value, so it is safe to put in a response header. */
    public enum Verdict {
        ACTIVE(null),
        SUSPENDED("suspended"),
        BANNED("banned"),
        UNRECOGNIZED("status-unrecognized");

        private final String reason;

        Verdict(String reason) {
            this.reason = reason;
        }

        /** Constant denial reason; {@code null} for {@link #ACTIVE}. */
        public String reason() {
            return reason;
        }
    }

    private SessionStatusPolicy() {
    }

    public static Verdict classify(String status) {
        if (asciiEqualsIgnoreCase(status, "active")) {
            return Verdict.ACTIVE;
        }
        if (asciiEqualsIgnoreCase(status, "suspended")) {
            return Verdict.SUSPENDED;
        }
        if (asciiEqualsIgnoreCase(status, "banned")) {
            return Verdict.BANNED;
        }
        return Verdict.UNRECOGNIZED;
    }

    /** {@code expected} must be lower-case ASCII. */
    private static boolean asciiEqualsIgnoreCase(String value, String expected) {
        if (value == null || value.length() != expected.length()) {
            return false;
        }
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c >= 'A' && c <= 'Z') {
                c = (char) (c + ('a' - 'A'));
            }
            if (c != expected.charAt(i)) {
                return false;
            }
        }
        return true;
    }
}
