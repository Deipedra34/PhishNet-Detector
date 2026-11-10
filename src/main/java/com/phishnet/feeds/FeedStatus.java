package com.phishnet.feeds;

import java.time.Instant;

/**
 * Where one feed stands, for {@code phishnet feeds status} and the verbose
 * scan report.
 *
 * @param refreshedAt last successful download, or {@code null} if never
 * @param entries     entries in the cached copy (0 if none)
 * @param lastError   why the most recent download failed, or {@code null}
 * @param detail      a short human-readable note (e.g. why it's not configured)
 */
public record FeedStatus(FeedSource source, State state, Instant refreshedAt, int entries, String lastError,
                         String detail) {

    public enum State {
        /** Cached copy within the refresh interval. */
        FRESH,
        /** Cached copy older than the refresh interval; still used until a refresh succeeds. */
        STALE,
        /** No usable cached copy: the feed is left out of scans. */
        MISSING,
        /** Turned off in the config. */
        DISABLED,
        /** Needs settings it doesn't have yet (e.g. an API key). */
        NOT_CONFIGURED,
        /** Threat feeds are off for this run ({@code --no-threat-feeds}, or a test with no network). */
        OFF;

        /** Whether a feed in this state takes part in matching. */
        public boolean available() {
            return this == FRESH || this == STALE;
        }
    }

    /**
     * One line for reports, e.g. "fresh, 41,230 entries, refreshed 2026-11-10T09:00:00Z"
     * or "not configured: no API key configured (...)". Without the feed's name.
     */
    public String describe() {
        StringBuilder text = new StringBuilder();
        switch (state) {
            case FRESH, STALE -> text.append(state == State.FRESH ? "fresh" : "stale")
                    .append(", ").append(entryCount(entries)).append(", refreshed ")
                    .append(refreshedAt);
            case MISSING -> text.append("unavailable (no cached copy yet)");
            case DISABLED -> text.append("disabled");
            case NOT_CONFIGURED -> text.append("not configured");
            case OFF -> text.append("off");
        }
        if (detail != null && !detail.isEmpty()) {
            text.append(state == State.FRESH || state == State.STALE || state == State.MISSING ? "; " : ": ")
                    .append(detail);
        } else if (lastError != null && state != State.FRESH) {
            text.append("; last download failed: ").append(lastError);
        }
        return text.toString();
    }

    /** "1 entry", "41,230 entries". */
    public static String entryCount(int entries) {
        return String.format("%,d %s", entries, entries == 1 ? "entry" : "entries");
    }
}
