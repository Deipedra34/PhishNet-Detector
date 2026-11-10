package com.phishnet.feeds;

import java.time.Instant;
import java.util.Objects;

/** One feed's entries as of its last successful download. */
public record FeedSnapshot(FeedSource source, FeedEntries entries, Instant refreshedAt) {

    public FeedSnapshot {
        Objects.requireNonNull(source, "source");
        Objects.requireNonNull(entries, "entries");
        Objects.requireNonNull(refreshedAt, "refreshedAt");
    }
}
