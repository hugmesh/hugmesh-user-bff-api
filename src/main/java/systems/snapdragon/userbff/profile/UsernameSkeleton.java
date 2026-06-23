package systems.snapdragon.userbff.profile;

import com.ibm.icu.text.SpoofChecker;
import systems.snapdragon.authcore.reserved.ReservedNames;

import java.text.Normalizer;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

/**
 * Confusable / look-alike "skeleton" folding for usernames and free-text display
 * names — the LOCAL, self-contained half of the platform username-confusable design
 * (the registry-owned {@code username_skeleton} table + the {@code /availability}
 * service endpoint live in snapdragon-federation-api; this copy gives user-bff a
 * fail-CLOSED reserved/reserved-confusable + zero-width/bidi guard with no network
 * round-trip, so {@code 4dmin / r00t / v4ult / akk0ma} are rejected even on a
 * federation outage).
 *
 * <h2>The skeleton is a RECOMPUTABLE CACHE, never a unique DB identity</h2>
 * ICU confusable skeletons are <b>not stable across ICU releases</b>
 * (icu4j is PINNED in {@code pom.xml} for exactly this reason). The skeleton is used
 * ONLY to REJECT a candidate at this defence-in-depth layer; the real DB backstop
 * stays the exact-username UNIQUE constraint + the {@code 004} {@code vanity_username}
 * CHECK + the {@link ReservedNames} exact-match rule, none of which this class
 * weakens.
 *
 * <h2>Algorithm (exact order — matches the federation copy)</h2>
 * <ol>
 *   <li>lowercase + trim (Locale.ROOT);</li>
 *   <li><b>REJECT</b> (do not strip) any default-ignorable / format (Cf) /
 *       zero-width (U+200B–200D, U+FEFF) / bidi-control (U+202A–202E, U+2066–2069)
 *       code point — BEFORE any folding, so a zero-width / bidi character cannot
 *       smuggle a look-alike past the fold (see {@link #hasForbiddenInvisible});</li>
 *   <li>NFKD normalize + strip combining marks (category Mn) — folds full-width /
 *       compatibility forms and diacritics;</li>
 *   <li>ASCII leet / homoglyph map ({@code 0→o, 1→i, 5→s, …}; deliberately NO
 *       {@code rn→m} / {@code vv→w} — documented ICU over-blockers). Applied BEFORE
 *       the ICU fold so a leet DIGIT becomes its letter first and ICU then folds the
 *       letter the SAME way it folds the reserved label (ICU's own digit fold picks
 *       {@code 1→l} / {@code 0→O}, which would otherwise diverge from this map);</li>
 *   <li>ICU {@link SpoofChecker} {@code getSkeleton} for the confusable fold
 *       (CONFUSABLE | RESTRICTION_LEVEL, MODERATELY_RESTRICTIVE), then lower-case
 *       (getSkeleton returns mixed case, e.g. {@code 0→O});</li>
 *   <li>strip separators ({@code - _ . space});</li>
 *   <li>collapse runs of length &ge;3 (so {@code anna / matt / sass} survive while
 *       {@code aaadmin→admin}, {@code roooot→root} still collapse their long runs).</li>
 * </ol>
 */
public final class UsernameSkeleton {

    private UsernameSkeleton() {}

    /** Reused, thread-safe ICU spoof checker (CONFUSABLE | MODERATELY_RESTRICTIVE). */
    private static final SpoofChecker SPOOF = new SpoofChecker.Builder()
            .setChecks(SpoofChecker.CONFUSABLE | SpoofChecker.RESTRICTION_LEVEL)
            .setRestrictionLevel(SpoofChecker.RestrictionLevel.MODERATELY_RESTRICTIVE)
            .build();

    /** Precomputed skeletons of every reserved label — built once at class load. */
    private static final Set<String> RESERVED_SKELETONS = buildReservedSkeletons();

    private static Set<String> buildReservedSkeletons() {
        var out = new HashSet<String>();
        for (String label : ReservedNames.RESERVED) {
            // Reserved labels are ASCII and free of invisibles, so skeleton() never
            // throws here; guard anyway so a future list addition can't break load.
            try {
                out.add(skeleton(label));
            } catch (RuntimeException ignored) {
                // skip an un-skeletonable label rather than fail class init
            }
        }
        return Set.copyOf(out);
    }

    /**
     * Whether {@code s} contains a forbidden invisible or direction-control code
     * point — default-ignorable, format (Cf), zero-width, or bidi-control. These are
     * rejected outright (a name is never allowed to carry them), independent of any
     * confusable fold. Used by the displayName charset guard.
     *
     * @param s the string to inspect (may be {@code null})
     * @return {@code true} when at least one forbidden code point is found;
     *         {@code false} when the string is {@code null} or contains none
     */
    public static boolean hasForbiddenInvisible(String s) {
        if (s == null) {
            return false;
        }
        int i = 0;
        while (i < s.length()) {
            int cp = s.codePointAt(i);
            if (isForbiddenInvisible(cp)) {
                return true;
            }
            i += Character.charCount(cp);
        }
        return false;
    }

    private static boolean isForbiddenInvisible(int cp) {
        // explicit zero-width + bidi-control ranges (belt-and-braces with the
        // category check below, which also covers other Cf code points)
        if (cp == 0xFEFF                       // ZERO WIDTH NO-BREAK SPACE / BOM
                || (cp >= 0x200B && cp <= 0x200F)   // zero-width + LRM/RLM
                || (cp >= 0x202A && cp <= 0x202E)   // LRE/RLE/PDF/LRO/RLO
                || (cp >= 0x2066 && cp <= 0x2069)) {// LRI/RLI/FSI/PDI
            return true;
        }
        int type = Character.getType(cp);
        return type == Character.FORMAT                // Cf
                || Character.isIdentifierIgnorable(cp);  // default-ignorable / controls
    }

    /**
     * The canonical confusable skeleton of {@code candidate} using the 6-step
     * algorithm (lowercase → forbiddenInvisible check → NFKD+stripMn → leet-map →
     * ICU getSkeleton → stripSeparators → collapseRepeats≥3).
     *
     * @param candidate the username or display-name candidate (may be {@code null})
     * @return the normalised skeleton string (never {@code null}; empty for
     *         {@code null} input)
     * @throws ConfusableException if the candidate carries a forbidden invisible or
     *         bidi-control code point (it cannot be safely folded and is rejected)
     */
    public static String skeleton(String candidate) {
        if (candidate == null) {
            return "";
        }
        String s = candidate.trim().toLowerCase(Locale.ROOT);
        if (hasForbiddenInvisible(s)) {
            throw new ConfusableException("contains a zero-width / bidi / format code point");
        }
        // NFKD + strip combining marks (Mn)
        String nfkd = Normalizer.normalize(s, Normalizer.Form.NFKD);
        StringBuilder stripped = new StringBuilder(nfkd.length());
        int i = 0;
        while (i < nfkd.length()) {
            int cp = nfkd.codePointAt(i);
            if (Character.getType(cp) != Character.NON_SPACING_MARK) {
                stripped.appendCodePoint(cp);
            }
            i += Character.charCount(cp);
        }
        // ASCII leet / homoglyph map BEFORE ICU (NO rn->m / vv->w) so a leet digit
        // becomes its letter and ICU then folds it the SAME way as the reserved label
        String leet = leetMap(stripped.toString());
        // ICU confusable fold, then lower-case (getSkeleton returns mixed case)
        String icu = SPOOF.getSkeleton(leet).toLowerCase(Locale.ROOT);
        // strip separators
        String noSep = icu.replaceAll("[-_. ]", "");
        // collapse runs of length >= 3
        return collapseRepeats(noSep);
    }

    /** Skeleton or {@code null} when the candidate is rejected (invisible/bidi). */
    private static String skeletonOrNull(String candidate) {
        try {
            return skeleton(candidate);
        } catch (ConfusableException ex) {
            return null;
        }
    }

    private static String leetMap(String s) {
        StringBuilder b = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '0' -> b.append('o');
                case '1', '|' -> b.append('i');   // 1 -> l -> i (final fold target)
                case '2' -> b.append('z');
                case '3' -> b.append('e');
                case '4' -> b.append('a');
                case '5', '$' -> b.append('s');
                case '7' -> b.append('t');
                case '8' -> b.append('b');
                case '9' -> b.append('g');
                case '@' -> b.append('a');
                default -> b.append(c);
            }
        }
        return b.toString();
    }

    /**
     * Collapse runs of the SAME character of length &ge;3 down to a single char, so
     * {@code rooot}/{@code roooot} both fold to {@code root} and {@code aaadmin} to
     * {@code admin}, while a genuine double from a length-2 run (e.g. {@code anna},
     * {@code matt}, {@code sass}) is preserved verbatim.
     */
    private static String collapseRepeats(String s) {
        if (s.length() < 3) {
            return s;
        }
        StringBuilder out = new StringBuilder(s.length());
        int i = 0;
        while (i < s.length()) {
            char c = s.charAt(i);
            int j = i;
            while (j < s.length() && s.charAt(j) == c) {
                j++;
            }
            int len = j - i;
            if (len >= 3) {
                out.append(c);                     // collapse >=3 to a single char
            } else {
                out.append(String.valueOf(c).repeat(len)); // keep 1 or 2 verbatim
            }
            i = j;
        }
        return out.toString();
    }

    /**
     * Whether {@code candidate}'s skeleton equals a reserved-label skeleton. Used to
     * reject reserved-confusables ({@code 4dmin~admin}, {@code akk0ma~akkoma}) — this
     * NEVER weakens the exact {@link ReservedNames#isReserved} rule, only widens it.
     *
     * @param candidate the username or display-name candidate (may be {@code null})
     * @return {@code true} when the candidate's skeleton matches a pre-computed
     *         reserved-label skeleton; {@code false} when null/blank, when carrying
     *         a forbidden invisible (skeleton rejected), or when no reserved match
     */
    public static boolean isReservedConfusable(String candidate) {
        if (candidate == null || candidate.isBlank()) {
            return false;
        }
        String skel = skeletonOrNull(candidate);
        return skel != null && !skel.isEmpty() && RESERVED_SKELETONS.contains(skel);
    }

    /** Thrown when a candidate carries a code point that cannot be safely folded
     *  (zero-width / bidi / format) — the candidate is rejected, not folded. */
    public static final class ConfusableException extends RuntimeException {
        public ConfusableException(String message) { super(message); }
    }
}
