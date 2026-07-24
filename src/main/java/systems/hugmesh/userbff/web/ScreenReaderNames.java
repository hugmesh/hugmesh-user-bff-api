package systems.hugmesh.userbff.web;

import systems.hugmesh.userbff.profile.UsernameSkeleton;

/**
 * The single home for the SCREEN-READER NAME charset rule + the display-name
 * ASCII/default/prompt logic, so the API-layer validator
 * ({@link SafeScreenReaderNameValidator}), the service-layer guard
 * ({@code ProfileService}), and the registration/profile-save default/prompt flow can
 * never drift.
 *
 * <p>A screen-reader name is the aria-label a screen reader announces, so it must be a
 * clean, pronounceable, ASCII string:
 * <ul>
 *   <li>{@link #isAscii(String)} — every code point is in printable ASCII
 *       (U+0020..U+007E). Anything outside (accented Latin, emoji, other scripts,
 *       control chars, the DEL char) is non-ASCII;</li>
 *   <li>{@link #isSafeScreenReaderName(String)} — ASCII printable AND free of the
 *       forbidden zero-width / bidi / format / default-ignorable code points
 *       ({@link UsernameSkeleton#hasForbiddenInvisible}). (The invisible check is
 *       redundant with the ASCII check — those code points are all &gt; U+007E — but
 *       kept explicit so the intent reads clearly and stays correct if the ASCII
 *       bound is ever widened.)</li>
 * </ul>
 *
 * <p>DEFAULT / PROMPT logic (the registration + profile-save contract):
 * <ul>
 *   <li>{@link #defaultFor(String)} — when a {@code displayName} is itself pure ASCII,
 *       the screen-reader name DEFAULTS to it (returns the display name); when the
 *       display name is non-ASCII it returns {@code null} (no safe default — a
 *       screen-reader name must be supplied);</li>
 *   <li>{@link #requiresScreenReaderName(String, String)} — true when a profile-save
 *       must PROMPT for a screen-reader name: the display name is non-ASCII AND no
 *       (ASCII-valid) screen-reader name was supplied. The save flow turns this into a
 *       422 so the UI can collect one.</li>
 * </ul>
 */
public final class ScreenReaderNames {

    private ScreenReaderNames() {}

    /** Highest printable ASCII code point (tilde). DEL (0x7F) and controls are out. */
    private static final int MAX_PRINTABLE_ASCII = 0x7E;
    /** Lowest printable ASCII code point (space). Below this are control chars. */
    private static final int MIN_PRINTABLE_ASCII = 0x20;

    /**
     * Whether EVERY code point of {@code s} is printable ASCII (U+0020..U+007E). A
     * {@code null}/blank string is treated as ASCII (it has no non-ASCII content) —
     * the absent/optional case is handled by the callers. Tab/newline and other
     * control chars are NOT printable ASCII, so they make a string non-ASCII here.
     */
    public static boolean isAscii(String s) {
        if (s == null || s.isEmpty()) {
            return true;
        }
        int i = 0;
        while (i < s.length()) {
            int cp = s.codePointAt(i);
            if (cp < MIN_PRINTABLE_ASCII || cp > MAX_PRINTABLE_ASCII) {
                return false;
            }
            i += Character.charCount(cp);
        }
        return true;
    }

    /**
     * Whether {@code s} is an acceptable screen-reader name: printable ASCII AND free
     * of forbidden invisibles. A {@code null}/blank value is acceptable (optional
     * field) — the default/prompt logic, not this charset check, decides whether one
     * is REQUIRED.
     */
    public static boolean isSafeScreenReaderName(String s) {
        if (s == null || s.isBlank()) {
            return true;
        }
        return isAscii(s) && !UsernameSkeleton.hasForbiddenInvisible(s);
    }

    /**
     * The screen-reader name to DEFAULT to for a given {@code displayName}: the
     * display name itself when it is pure ASCII, else {@code null} (no safe default —
     * a non-ASCII display name needs an explicit ASCII screen-reader name).
     */
    public static String defaultFor(String displayName) {
        if (displayName == null || displayName.isBlank()) {
            return null;
        }
        return isAscii(displayName) ? displayName : null;
    }

    /**
     * Whether a profile-save must PROMPT the user for a screen-reader name: the
     * display name is present + NON-ASCII and no usable screen-reader name was
     * supplied (null/blank, OR a value that is not itself a safe ASCII name). When this
     * is true the save flow returns a 422 so the UI can collect a screen-reader name.
     */
    public static boolean requiresScreenReaderName(String displayName, String screenReaderName) {
        if (displayName == null || displayName.isBlank() || isAscii(displayName)) {
            return false; // ASCII (or absent) display name defaults — never prompts.
        }
        // Non-ASCII display name: a usable ASCII screen-reader name must be present.
        return screenReaderName == null || screenReaderName.isBlank()
                || !isSafeScreenReaderName(screenReaderName);
    }
}
