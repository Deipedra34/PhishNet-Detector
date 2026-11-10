package com.phishnet.feeds;

/**
 * A threat intelligence feed of known phishing URLs. {@link #displayName()} is
 * what the user sees in signal labels ("Known phishing URL (OpenPhish)") and in
 * {@code phishnet feeds status}; {@link #id()} names its files in the cache
 * directory.
 */
public enum FeedSource {
    OPENPHISH("openphish", "OpenPhish"),
    PHISHTANK("phishtank", "PhishTank");

    private final String id;
    private final String displayName;

    FeedSource(String id, String displayName) {
        this.id = id;
        this.displayName = displayName;
    }

    /** Stable lowercase identifier, used for cache file names. */
    public String id() {
        return id;
    }

    public String displayName() {
        return displayName;
    }
}
