package com.phishnet.util;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class HomoglyphUtilTest {

    @Test
    void pureLatinIsNotMixedScript() {
        assertFalse(HomoglyphUtil.isMixedScript("apple"));
    }

    @Test
    void pureCyrillicIsNotMixedScript() {
        // fully Cyrillic "apple" look-alike (а, р, р, palochka, е): single script, so no mix
        assertFalse(HomoglyphUtil.isMixedScript("аррӏе"));
    }

    @Test
    void latinWithCyrillicSubstitutionIsMixedScript() {
        // Latin "pple" with a Cyrillic 'а' standing in for the first letter
        String partiallySpoofed = "аpple"; // Cyrillic а + Latin pple
        assertTrue(HomoglyphUtil.isMixedScript(partiallySpoofed));
    }

    @Test
    void digitsAndPunctuationDoNotCountAsScriptMix() {
        assertFalse(HomoglyphUtil.isMixedScript("apple-123.com"));
    }

    @Test
    void detectsPunycodeLabel() {
        assertTrue(HomoglyphUtil.containsPunycodeLabel("xn--80ak6aa92e.com"));
        assertFalse(HomoglyphUtil.containsPunycodeLabel("apple.com"));
    }

    @Test
    void decodesPunycodeHostToUnicode() {
        String cyrillicSpoofedHost = "аpple.com"; // Cyrillic а + Latin "pple.com"
        String encoded = java.net.IDN.toASCII(cyrillicSpoofedHost);
        assertTrue(encoded.contains("xn--"));

        String decoded = HomoglyphUtil.decodeHost(encoded);
        assertFalse(decoded.contains("xn--"));
        assertEquals(cyrillicSpoofedHost, decoded);
    }

    @Test
    void skeletonNormalizesCyrillicConfusablesToLatin() {
        // Fully Cyrillic look-alike of "apple" using confusable characters
        String cyrillicApple = "аррӏе"; // а р р palochka е
        assertEquals("apple", HomoglyphUtil.toAsciiSkeleton(cyrillicApple));
    }

    @Test
    void skeletonOfPlainAsciiIsJustLowercased() {
        assertEquals("microsoft", HomoglyphUtil.toAsciiSkeleton("Microsoft"));
    }

    // --- malformed / edge-case input -----------------------------------------

    @Test
    void malformedPunycodeLabelDoesNotThrowAndIsReturnedUnchanged() {
        // "xn--" with no valid ACE payload after it is not decodable.
        String malformed = "xn--.com";
        String decoded = assertDoesNotThrow(() -> HomoglyphUtil.decodeHost(malformed));
        assertEquals(malformed, decoded);
    }

    @Test
    void nullHostDecodesToNullWithoutThrowing() {
        assertDoesNotThrow(() -> HomoglyphUtil.decodeHost(null));
    }

    @Test
    void emptyHostIsNotFlaggedAsPunycode() {
        assertFalse(HomoglyphUtil.containsPunycodeLabel(""));
    }

    @Test
    void nullHostIsNotFlaggedAsPunycode() {
        assertFalse(HomoglyphUtil.containsPunycodeLabel(null));
    }

    @Test
    void emptyStringIsNotMixedScript() {
        assertFalse(HomoglyphUtil.isMixedScript(""));
    }

    @Test
    void nullStringIsNotMixedScript() {
        assertFalse(HomoglyphUtil.isMixedScript(null));
    }

    @Test
    void skeletonOfEmptyStringIsEmpty() {
        assertEquals("", HomoglyphUtil.toAsciiSkeleton(""));
    }
}
