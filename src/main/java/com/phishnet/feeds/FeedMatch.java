package com.phishnet.feeds;

/**
 * A scanned URL found in a feed.
 *
 * @param entry the matching feed key: the URL itself for {@link Kind#URL}, the host for {@link Kind#DOMAIN}
 */
public record FeedMatch(FeedSource source, Kind kind, String entry, FeedSnapshot snapshot) {

    public enum Kind {
        /** This exact URL (after normalization) is listed. */
        URL,
        /** This URL isn't listed, but other URLs on the same host are. */
        DOMAIN
    }
}
