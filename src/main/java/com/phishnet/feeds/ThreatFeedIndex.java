package com.phishnet.feeds;

import com.phishnet.model.Signal;
import com.phishnet.model.SignalCategory;
import com.phishnet.scoring.RiskScorer;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

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

    /**
     * The scoring signals for {@code rawUrl}: one {@value RiskScorer#KNOWN_PHISHING_URL}
     * signal if any feed lists this exact URL, labeled with every feed that does
     * ("Known phishing URL (OpenPhish, PhishTank)"); otherwise one
     * {@value RiskScorer#KNOWN_PHISHING_DOMAIN} signal if any feed lists other URLs on
     * its host. Never both, and never one per feed, so being listed twice doesn't
     * count twice. Empty if nothing matches or no feed data is loaded.
     */
    public List<Signal> signalsFor(String rawUrl) {
        return signalsForAny(List.of(rawUrl));
    }

    /**
     * Like {@link #signalsFor(String)}, but over several URLs at once (the links
     * in an email): still at most one feed signal in total, a URL-level one if
     * any of them is listed, otherwise a domain-level one if any of their hosts is.
     */
    public List<Signal> signalsForAny(Collection<String> rawUrls) {
        List<FeedMatch> matches = new ArrayList<>();
        for (String rawUrl : rawUrls) {
            matches.addAll(matches(rawUrl));
        }
        List<FeedMatch> urlMatches = matches.stream().filter(m -> m.kind() == FeedMatch.Kind.URL).toList();
        if (!urlMatches.isEmpty()) {
            return List.of(new Signal(RiskScorer.KNOWN_PHISHING_URL, SignalCategory.URL,
                    "Known phishing URL (" + sources(urlMatches) + ")", evidence(urlMatches)));
        }
        if (!matches.isEmpty()) {
            return List.of(new Signal(RiskScorer.KNOWN_PHISHING_DOMAIN, SignalCategory.DOMAIN,
                    "Known phishing domain (" + sources(matches) + "): other URLs on this host are listed",
                    evidence(matches)));
        }
        return List.of();
    }

    private static String sources(List<FeedMatch> matches) {
        return matches.stream().map(m -> m.source().displayName()).distinct().collect(Collectors.joining(", "));
    }

    private static String evidence(List<FeedMatch> matches) {
        return matches.stream()
                .distinct()
                .map(m -> m.entry() + " listed in " + m.source().displayName() + ", feed refreshed "
                        + m.snapshot().refreshedAt())
                .collect(Collectors.joining("; "));
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
