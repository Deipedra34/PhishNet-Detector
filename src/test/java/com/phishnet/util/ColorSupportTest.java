package com.phishnet.util;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ColorSupportTest {

    @Test
    void enabledOnlyWhenTtyAndNoOverridesPresent() {
        assertTrue(ColorSupport.isEnabled(false, true, false));
    }

    @Test
    void noColorFlagDisablesEvenOnATty() {
        assertFalse(ColorSupport.isEnabled(true, true, false));
    }

    @Test
    void notATtyDisablesRegardlessOfFlags() {
        assertFalse(ColorSupport.isEnabled(false, false, false));
    }

    @Test
    void noColorEnvVarDisablesEvenOnATty() {
        assertFalse(ColorSupport.isEnabled(false, true, true));
    }

    @Test
    void allDisablingConditionsAtOnceStillDisabled() {
        assertFalse(ColorSupport.isEnabled(true, false, true));
    }

    @Test
    void notATtyWithNoColorFlagAlsoDisabled() {
        assertFalse(ColorSupport.isEnabled(true, false, false));
    }

    @Test
    void singleArgOverloadDoesNotThrow() {
        // Exercises the real System.console()/getenv path; under the test
        // runner this is never a real TTY, so it should come back false.
        boolean result = ColorSupport.isEnabled(false);
        assertFalse(result);
    }

    @Test
    void singleArgOverloadWithNoColorFlagIsAlwaysFalse() {
        assertFalse(ColorSupport.isEnabled(true));
    }
}
