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
}
