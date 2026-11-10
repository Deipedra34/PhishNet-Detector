package com.phishnet.feeds;

import java.time.Duration;
import java.time.Instant;

/** How usable a feed's cached copy is right now. */
public enum FeedFreshness {
    /** Refreshed within the refresh interval: used as-is, no download. */
    FRESH,
    /** Older than the refresh interval: a refresh is attempted, and this copy is the fallback. */
    STALE,
    /** Never successfully downloaded: the feed contributes nothing until it is. */
    MISSING;

    /**
     * Classifies a cache last refreshed at {@code refreshedAt} ({@code null} if
     * never), given the refresh interval. A cache exactly {@code refreshInterval}
     * old is stale. A timestamp in the future (a clock change) counts as fresh.
     */
    public static FeedFreshness of(Instant refreshedAt, Duration refreshInterval, Instant now) {
        if (refreshedAt == null) {
            return MISSING;
        }
        return Duration.between(refreshedAt, now).compareTo(refreshInterval) < 0 ? FRESH : STALE;
    }
}
