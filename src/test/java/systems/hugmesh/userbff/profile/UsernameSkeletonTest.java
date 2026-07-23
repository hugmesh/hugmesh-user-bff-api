package systems.hugmesh.userbff.profile;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for the LOCAL confusable {@link UsernameSkeleton} engine — the
 * defence-in-depth half user-bff carries so reserved / reserved-confusable names are
 * rejected even on a federation outage. Proves the algorithm folds look-alikes onto
 * the reserved-label skeleton, preserves legitimate doubled-letter names, and rejects
 * invisible / bidi code points outright.
 */
class UsernameSkeletonTest {

    // --- reserved-confusable detection (the user-bff guard surface) ---

    @ParameterizedTest
    @ValueSource(strings = {
            "admin", "ADMIN", "Admin",     // exact (case-insensitive)
            "4dmin", "adm1n", "@dmin",     // leet homoglyphs
            "ad-min", "ad_min", "a.dmin",  // separator-stripped
            "aaadmin",                     // collapsed >=3 run folds onto admin
            "r00t", "ro0t",                // root leet (0 -> o)
            "v4ult",                       // vault leet (4 -> a)
    })
    void reservedConfusables_areDetected(String candidate) {
        assertThat(UsernameSkeleton.isReservedConfusable(candidate))
                .as("'%s' should be confusable with a reserved label", candidate)
                .isTrue();
    }

    @ParameterizedTest
    @ValueSource(strings = {"alice", "carol", "bob", "zoe", "dave", "erin", "frank"})
    void ordinaryNames_areNotReservedConfusable(String candidate) {
        assertThat(UsernameSkeleton.isReservedConfusable(candidate)).isFalse();
    }

    @Test
    void cyrillicLookAlikeOfAdmin_isReservedConfusable() {
        // 'а' (U+0430 CYRILLIC SMALL A) + 'd' 'm' 'i' 'n' — a classic homograph of
        // ASCII "admin"; ICU getSkeleton folds the Cyrillic 'а' onto ASCII 'a'.
        String cyrillic = "аdmin";
        assertThat(cyrillic).isNotEqualTo("admin"); // genuinely different code points
        assertThat(UsernameSkeleton.isReservedConfusable(cyrillic)).isTrue();
    }

    // --- false-positive guards: legitimate doubled names survive ---

    @ParameterizedTest
    @ValueSource(strings = {"anna", "matt", "sass", "emma", "jess"})
    void doubledLetterNames_areNotCollapsedIntoReserved(String name) {
        // a length-2 run is preserved (only runs >=3 collapse), so these are NOT
        // accidentally folded onto a shorter reserved skeleton.
        assertThat(UsernameSkeleton.isReservedConfusable(name)).isFalse();
    }

    @Test
    void collapseOnlyAppliesToRunsOfThreeOrMore() {
        // "anna" (run of 2) keeps its double; "annna" (run of 3) collapses to one.
        assertThat(UsernameSkeleton.skeleton("anna")).isEqualTo("anna");
        assertThat(UsernameSkeleton.skeleton("annna")).isEqualTo("ana");
        // a >=3 run collapses to a SINGLE char (so rooot/roooot share a skeleton);
        // "root" itself has only a run of 2 and is preserved.
        assertThat(UsernameSkeleton.skeleton("rooot")).isEqualTo("rot");
        assertThat(UsernameSkeleton.skeleton("roooot")).isEqualTo("rot");
        assertThat(UsernameSkeleton.skeleton("root")).isEqualTo("root");
        // "aaadmin" (run of 3 a's) collapses onto admin's skeleton.
        assertThat(UsernameSkeleton.skeleton("aaadmin"))
                .isEqualTo(UsernameSkeleton.skeleton("admin"));
    }

    // --- invisible / bidi rejection ---

    @ParameterizedTest
    @ValueSource(strings = {
            "ad​min",   // ZERO WIDTH SPACE
            "ad‌min",   // ZERO WIDTH NON-JOINER
            "ad‍min",   // ZERO WIDTH JOINER
            "﻿admin",   // BOM / ZWNBSP
            "ad‮min",   // RIGHT-TO-LEFT OVERRIDE (bidi)
            "ad⁦min",   // LEFT-TO-RIGHT ISOLATE (bidi)
    })
    void invisibleAndBidiCodePoints_areDetected(String candidate) {
        assertThat(UsernameSkeleton.hasForbiddenInvisible(candidate))
                .as("'%s' carries a forbidden invisible/bidi code point", candidate)
                .isTrue();
        // and skeleton() rejects rather than silently folds them
        assertThatThrownBy(() -> UsernameSkeleton.skeleton(candidate))
                .isInstanceOf(UsernameSkeleton.ConfusableException.class);
    }

    @Test
    void plainAsciiName_hasNoForbiddenInvisible() {
        assertThat(UsernameSkeleton.hasForbiddenInvisible("alice")).isFalse();
        assertThat(UsernameSkeleton.hasForbiddenInvisible("anna-maria")).isFalse();
    }

    @Test
    void nullAndBlank_areSafeDefaults() {
        assertThat(UsernameSkeleton.isReservedConfusable(null)).isFalse();
        assertThat(UsernameSkeleton.isReservedConfusable("")).isFalse();
        assertThat(UsernameSkeleton.hasForbiddenInvisible(null)).isFalse();
        assertThat(UsernameSkeleton.skeleton(null)).isEmpty();
    }
}
