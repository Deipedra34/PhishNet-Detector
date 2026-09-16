package com.phishnet.util;

/**
 * Pure string formatting for a batch-mode progress line, e.g.
 * {@code [########------------] 40% (12/30) ETA 0:18}. Kept free of any
 * terminal/streaming concerns so the format itself is trivially unit-testable.
 */
public final class ProgressBarFormatter {

    private static final int BAR_WIDTH = 20;

    private ProgressBarFormatter() {
    }

    /**
     * @param completed     items scanned so far (clamped into [0, total])
     * @param total         total items to scan; treated as 1 for percentage math if 0 (empty batch)
     * @param elapsedMillis wall-clock time since scanning started, used for the ETA estimate
     */
    public static String format(int completed, int total, long elapsedMillis) {
        int safeTotal = Math.max(total, 1);
        int clamped = Math.min(Math.max(completed, 0), safeTotal);
        int percent = (int) ((clamped * 100L) / safeTotal);
        int filled = (int) ((clamped * (long) BAR_WIDTH) / safeTotal);

        StringBuilder bar = new StringBuilder(BAR_WIDTH);
        for (int i = 0; i < BAR_WIDTH; i++) {
            bar.append(i < filled ? '#' : '-');
        }

        StringBuilder line = new StringBuilder();
        line.append('[').append(bar).append("] ")
                .append(percent).append("% (")
                .append(clamped).append('/').append(total).append(')');

        String eta = formatEta(clamped, total, elapsedMillis);
        if (eta != null) {
            line.append(' ').append(eta);
        }
        return line.toString();
    }

    /** Null once done (or before there's enough data to estimate from). */
    private static String formatEta(int completed, int total, long elapsedMillis) {
        if (completed <= 0 || completed >= total || elapsedMillis <= 0) {
            return null;
        }
        long remainingMillis = elapsedMillis * (total - completed) / completed;
        return "ETA " + formatDuration(remainingMillis);
    }

    private static String formatDuration(long millis) {
        long totalSeconds = millis / 1000;
        long minutes = totalSeconds / 60;
        long seconds = totalSeconds % 60;
        return String.format("%d:%02d", minutes, seconds);
    }
}
