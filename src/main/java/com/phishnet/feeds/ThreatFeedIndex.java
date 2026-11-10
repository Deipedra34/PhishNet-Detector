package com.phishnet.feeds;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * The feeds available to one run, ready for lookups: every cached snapshot
 * that could be loaded, plus each feed's status (so a report can tell "not
 * listed" apart from "no feed data"). Immutable and safe to share across the
 * threads of a parallel batch scan.
 */
public final class ThreatFeedIndex {

    private final List<FeedSnapshot> snapshots;
    private final List<FeedStatus> statuses;
    private final Set<String> sharedHosts;

    /**
     * @param sharedHosts hosts where many unrelated sites live (shared hosting,
     *                    file sharing): a listed page there says nothing about
     *                    the rest of the host, so they never produce a domain match
     */
    public ThreatFeedIndex(List<FeedSnapshot> snapshots, List<FeedStatus> statuses, Set<String> sharedHosts) {
        this.snapshots = List.copyOf(snapshots);
        this.statuses = List.copyOf(statuses);
        this.sharedHosts = Set.copyOf(sharedHosts);
    }

    /** No feed data at all - what {@code --no-threat-feeds} uses. */
    public static ThreatFeedIndex empty(List<FeedStatus> statuses) {
        return new ThreatFeedIndex(List.of(), statuses, Set.of());
    }

    public List<FeedSnapshot> snapshots() {
        return snapshots;
    }

    public List<FeedStatus> statuses() {
        return statuses;
    }

    /** Whether any feed data is loaded. */
    public boolean isEmpty() {
        return snapshots.isEmpty();
    }

    /**
     * Every feed listing {@code rawUrl}: an exact URL match wherever there is
     * one, otherwise a domain match where the host appears in that feed (and
     * isn't a shared host). At most one match per feed.
     */
    public List<FeedMatch> matches(String rawUrl) {
        List<FeedMatch> matches = new ArrayList<>();
        if (snapshots.isEmpty()) {
            return matches;
        }
        Optional<String> key = FeedUrls.normalize(rawUrl);
        if (key.isEmpty()) {
            return matches;
        }
        String host = FeedUrls.hostOfKey(key.get());
        for (FeedSnapshot snapshot : snapshots) {
            FeedEntries entries = snapshot.entries();
            if (entries.containsUrl(key.get())) {
                matches.add(new FeedMatch(snapshot.source(), FeedMatch.Kind.URL, key.get(), snapshot));
            } else if (!isShared(host) && entries.containsHost(host)) {
                matches.add(new FeedMatch(snapshot.source(), FeedMatch.Kind.DOMAIN, host, snapshot));
            }
        }
        return matches;
    }

    /** {@code host} is a shared host itself, or a subdomain of one listed with a leading dot. */
    private boolean isShared(String host) {
        if (sharedHosts.contains(host)) {
            return true;
        }
        for (String shared : sharedHosts) {
            if (shared.startsWith(".") && host.endsWith(shared)) {
                return true;
            }
        }
        return false;
    }
}
