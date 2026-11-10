package com.phishnet.feeds;

/**
 * The outcome of one download attempt.
 *
 * @param entries entries in the new copy (UPDATED only)
 * @param message what happened, for the user: an error, or why the feed was skipped
 */
public record FeedRefreshResult(FeedSource source, Outcome outcome, int entries, String message) {

    public enum Outcome {
        /** Downloaded, parsed, and written to the cache. */
        UPDATED,
        /** Not attempted (disabled, not configured, or feeds off for this run). */
        SKIPPED,
        /** Attempted and failed; any previously cached copy is untouched. */
        FAILED
    }

    static FeedRefreshResult updated(FeedSource source, int entries) {
        return new FeedRefreshResult(source, Outcome.UPDATED, entries, "");
    }

    static FeedRefreshResult skipped(FeedSource source, String reason) {
        return new FeedRefreshResult(source, Outcome.SKIPPED, 0, reason);
    }

    static FeedRefreshResult failed(FeedSource source, String error) {
        return new FeedRefreshResult(source, Outcome.FAILED, 0, error);
    }
}
