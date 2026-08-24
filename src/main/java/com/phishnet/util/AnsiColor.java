package com.phishnet.util;

/** Plain ANSI escape codes for terminal output - no external dependency needed. */
public enum AnsiColor {
    RESET("[0m"),
    BOLD("[1m"),
    RED("[31m"),
    YELLOW("[33m"),
    GREEN("[32m");

    private final String code;

    AnsiColor(String code) {
        this.code = code;
    }

    public String code() {
        return code;
    }

    @Override
    public String toString() {
        return code;
    }

    /** Wraps text in the given styles, then RESET. Returns text unchanged if disabled or no styles given. */
    public static String apply(String text, boolean enabled, AnsiColor... styles) {
        if (!enabled || styles.length == 0) {
            return text;
        }
        StringBuilder sb = new StringBuilder();
        for (AnsiColor style : styles) {
            sb.append(style.code());
        }
        sb.append(text).append(RESET.code());
        return sb.toString();
    }
}
