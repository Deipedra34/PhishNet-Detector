package com.phishnet.util;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AnsiColorTest {

    private static final char ESC = '';

    @Test
    void codesStartWithEscapeCharacter() {
        for (AnsiColor color : AnsiColor.values()) {
            assertEquals(ESC, color.code().charAt(0));
        }
    }

    @Test
    void applyReturnsPlainTextWhenDisabled() {
        assertEquals("HIGH", AnsiColor.apply("HIGH", false, AnsiColor.BOLD, AnsiColor.RED));
    }

    @Test
    void applyReturnsPlainTextWhenNoStylesGiven() {
        assertEquals("HIGH", AnsiColor.apply("HIGH", true));
    }

    @Test
    void applyWrapsTextInCodesWhenEnabled() {
        String result = AnsiColor.apply("HIGH", true, AnsiColor.RED);
        assertTrue(result.startsWith(AnsiColor.RED.code()));
        assertTrue(result.contains("HIGH"));
        assertTrue(result.endsWith(AnsiColor.RESET.code()));
    }

    @Test
    void applyCombinesMultipleStylesInOrder() {
        String result = AnsiColor.apply("HIGH", true, AnsiColor.BOLD, AnsiColor.RED);
        String expected = AnsiColor.BOLD.code() + AnsiColor.RED.code() + "HIGH" + AnsiColor.RESET.code();
        assertEquals(expected, result);
    }

    @Test
    void disabledOutputNeverContainsEscapeCharacter() {
        String result = AnsiColor.apply("safe for piping", false, AnsiColor.BOLD, AnsiColor.RED, AnsiColor.YELLOW);
        assertEquals(-1, result.indexOf(ESC));
    }

    @Test
    void colorsAreDistinct() {
        assertFalse(AnsiColor.RED.code().equals(AnsiColor.YELLOW.code()));
        assertFalse(AnsiColor.YELLOW.code().equals(AnsiColor.GREEN.code()));
        assertFalse(AnsiColor.RED.code().equals(AnsiColor.GREEN.code()));
    }
}
