package com.phishnet.util;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class LevenshteinDistanceTest {

    @Test
    void identicalStringsHaveZeroDistance() {
        assertEquals(0, LevenshteinDistance.distance("paypal", "paypal"));
    }

    @Test
    void oneSubstitutionCountsAsOne() {
        assertEquals(1, LevenshteinDistance.distance("paypal", "paypa1"));
    }

    @Test
    void oneInsertionCountsAsOne() {
        assertEquals(1, LevenshteinDistance.distance("google", "gooogle"));
    }

    @Test
    void oneDeletionCountsAsOne() {
        assertEquals(1, LevenshteinDistance.distance("microsoft", "microsft"));
    }

    @Test
    void completelyDifferentStringsCostLengthOfLongest() {
        assertEquals(6, LevenshteinDistance.distance("abcdef", ""));
        assertEquals(6, LevenshteinDistance.distance("", "abcdef"));
    }

    @Test
    void emptyAndNullAreTreatedAsEmptyString() {
        assertEquals(0, LevenshteinDistance.distance(null, null));
        assertEquals(5, LevenshteinDistance.distance(null, "apple"));
    }

    @Test
    void isSymmetric() {
        assertEquals(LevenshteinDistance.distance("amazon", "amaz0n"),
                LevenshteinDistance.distance("amaz0n", "amazon"));
    }
}
