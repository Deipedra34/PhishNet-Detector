package com.phishnet.util;

/**
 * Decides whether CLI output should be colored. The actual decision logic is
 * a pure function of three booleans so it's easy to test; isEnabled(boolean)
 * is the convenience overload that reads the real environment.
 */
public final class ColorSupport {

    private ColorSupport() {
    }

    /**
     * True only if none of the disabling conditions apply: no --no-color
     * flag, output is going to a real terminal, and NO_COLOR isn't set.
     */
    public static boolean isEnabled(boolean noColorFlag, boolean isTty, boolean noColorEnvSet) {
        return !noColorFlag && isTty && !noColorEnvSet;
    }

    /** Same decision, reading the real console/env state. */
    public static boolean isEnabled(boolean noColorFlag) {
        return isEnabled(noColorFlag, System.console() != null, System.getenv("NO_COLOR") != null);
    }
}
