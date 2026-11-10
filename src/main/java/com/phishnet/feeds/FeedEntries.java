package com.phishnet.feeds;

import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 * The parsed contents of one feed: normalized URL keys (see {@link FeedUrls})
 * plus the set of hosts they're on, both as hash sets for constant-time lookup
 * during a scan.
 */
public final class FeedEntries {

    private final Set<String> urls;
    private final Set<String> hosts;
    private final int skipped;

    private FeedEntries(Set<String> urls, int skipped) {
        Set<String> hostSet = new HashSet<>();
        for (String key : urls) {
            hostSet.add(FeedUrls.hostOfKey(key));
        }
        this.urls = Collections.unmodifiableSet(urls);
        this.hosts = Collections.unmodifiableSet(hostSet);
        this.skipped = skipped;
    }

    /** Entries from already-normalized keys, as read back from the cache. */
    public static FeedEntries ofKeys(Collection<String> keys) {
        return new FeedEntries(new HashSet<>(keys), 0);
    }

    /** Entries from normalized keys, remembering how many raw entries couldn't be parsed. */
    static FeedEntries ofKeys(Collection<String> keys, int skipped) {
        return new FeedEntries(new HashSet<>(keys), skipped);
    }

    public static FeedEntries empty() {
        return new FeedEntries(new HashSet<>(), 0);
    }

    public Set<String> urls() {
        return urls;
    }

    public Set<String> hosts() {
        return hosts;
    }

    public int size() {
        return urls.size();
    }

    /** Raw entries dropped while parsing because they had no usable host. */
    public int skipped() {
        return skipped;
    }

    public boolean containsUrl(String key) {
        return urls.contains(key);
    }

    public boolean containsHost(String host) {
        return hosts.contains(host);
    }
}
