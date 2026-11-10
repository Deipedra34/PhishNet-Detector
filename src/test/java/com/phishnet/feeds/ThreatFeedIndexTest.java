package com.phishnet.feeds;

import com.phishnet.model.Signal;
import com.phishnet.model.SignalCategory;
import com.phishnet.scoring.RiskScorer;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ThreatFeedIndexTest {

    private static final Instant REFRESHED = Instant.parse("2026-11-10T11:00:00Z");

    private static FeedSnapshot snapshot(FeedSource source, String... keys) {
        return new FeedSnapshot(source, FeedEntries.ofKeys(List.of(keys)), REFRESHED);
    }

    private static ThreatFeedIndex index(Set<String> sharedHosts, FeedSnapshot... snapshots) {
        return new ThreatFeedIndex(List.of(snapshots), List.of(), sharedHosts);
    }

    @Test
    void exactUrlMatchIgnoresSchemeWwwAndTrailingSlash() {
        ThreatFeedIndex index = index(Set.of(), snapshot(FeedSource.OPENPHISH, "evil.example/login"));

        List<FeedMatch> matches = index.matches("HTTPS://www.Evil.example/login/");

        assertEquals(1, matches.size());
        assertEquals(FeedMatch.Kind.URL, matches.get(0).kind());
        assertEquals(FeedSource.OPENPHISH, matches.get(0).source());
    }

    @Test
    void otherUrlOnAListedHostIsADomainMatch() {
        ThreatFeedIndex index = index(Set.of(), snapshot(FeedSource.OPENPHISH, "evil.example/login"));

        List<FeedMatch> matches = index.matches("https://evil.example/other-page");

        assertEquals(1, matches.size());
        assertEquals(FeedMatch.Kind.DOMAIN, matches.get(0).kind());
        assertEquals("evil.example", matches.get(0).entry());
    }

    @Test
    void unlistedUrlDoesNotMatch() {
        ThreatFeedIndex index = index(Set.of(), snapshot(FeedSource.OPENPHISH, "evil.example/login"));

        assertTrue(index.matches("https://example.com/login").isEmpty());
        // A subdomain is a different host: feeds list exact hosts.
        assertTrue(index.matches("https://login.evil.example/login").isEmpty());
        assertTrue(index.signalsFor("https://example.com/").isEmpty());
    }

    @Test
    void sharedHostsOnlyMatchExactUrls() {
        ThreatFeedIndex index = index(Set.of("sites.google.com", ".ipfs.example"),
                snapshot(FeedSource.OPENPHISH, "sites.google.com/view/fake-bank", "abc.ipfs.example/phish"));

        assertEquals(FeedMatch.Kind.URL, index.matches("https://sites.google.com/view/fake-bank").get(0).kind());
        assertTrue(index.matches("https://sites.google.com/view/my-bakery").isEmpty());
        // A leading dot covers every subdomain.
        assertTrue(index.matches("https://abc.ipfs.example/other").isEmpty());
        assertEquals(1, index.matches("https://abc.ipfs.example/phish").size());
    }

    @Test
    void urlListedInBothFeedsMatchesEach() {
        ThreatFeedIndex index = index(Set.of(),
                snapshot(FeedSource.OPENPHISH, "evil.example/login"),
                snapshot(FeedSource.PHISHTANK, "evil.example/login"));

        assertEquals(2, index.matches("http://evil.example/login").size());
    }

    @Test
    void urlMatchBecomesOneKnownPhishingUrlSignal() {
        ThreatFeedIndex index = index(Set.of(), snapshot(FeedSource.OPENPHISH, "evil.example/login"));

        List<Signal> signals = index.signalsFor("https://evil.example/login");

        assertEquals(1, signals.size());
        Signal signal = signals.get(0);
        assertEquals(RiskScorer.KNOWN_PHISHING_URL, signal.id());
        assertEquals(SignalCategory.URL, signal.category());
        assertEquals("Known phishing URL (OpenPhish)", signal.description());
        assertTrue(signal.evidence().contains("evil.example/login listed in OpenPhish"), signal.evidence());
        assertTrue(signal.evidence().contains(REFRESHED.toString()), signal.evidence());
    }

    @Test
    void phishTankMatchIsLabeledPhishTank() {
        ThreatFeedIndex index = index(Set.of(), snapshot(FeedSource.PHISHTANK, "evil.example/login"));

        assertEquals("Known phishing URL (PhishTank)", index.signalsFor("https://evil.example/login").get(0).description());
    }

    @Test
    void urlListedInBothFeedsIsStillOneSignalNamingBoth() {
        ThreatFeedIndex index = index(Set.of(),
                snapshot(FeedSource.OPENPHISH, "evil.example/login"),
                snapshot(FeedSource.PHISHTANK, "evil.example/login"));

        List<Signal> signals = index.signalsFor("https://evil.example/login");

        assertEquals(1, signals.size());
        assertEquals("Known phishing URL (OpenPhish, PhishTank)", signals.get(0).description());
    }

    @Test
    void urlMatchInOneFeedOutranksADomainMatchInAnother() {
        ThreatFeedIndex index = index(Set.of(),
                snapshot(FeedSource.OPENPHISH, "evil.example/other"),
                snapshot(FeedSource.PHISHTANK, "evil.example/login"));

        List<Signal> signals = index.signalsFor("https://evil.example/login");

        assertEquals(1, signals.size());
        assertEquals(RiskScorer.KNOWN_PHISHING_URL, signals.get(0).id());
        assertEquals("Known phishing URL (PhishTank)", signals.get(0).description());
    }

    @Test
    void domainMatchBecomesOneKnownPhishingDomainSignal() {
        ThreatFeedIndex index = index(Set.of(), snapshot(FeedSource.OPENPHISH, "evil.example/login"));

        List<Signal> signals = index.signalsFor("https://evil.example/");

        assertEquals(1, signals.size());
        assertEquals(RiskScorer.KNOWN_PHISHING_DOMAIN, signals.get(0).id());
        assertEquals(SignalCategory.DOMAIN, signals.get(0).category());
        assertTrue(signals.get(0).description().startsWith("Known phishing domain (OpenPhish)"));
    }

    @Test
    void severalLinksProduceAtMostOneSignal() {
        ThreatFeedIndex index = index(Set.of(),
                snapshot(FeedSource.OPENPHISH, "evil.example/login", "worse.example/pay"));

        List<Signal> signals = index.signalsForAny(List.of(
                "https://example.com/", "https://evil.example/login", "https://worse.example/pay"));

        assertEquals(1, signals.size());
        assertEquals(RiskScorer.KNOWN_PHISHING_URL, signals.get(0).id());
        assertEquals("Known phishing URL (OpenPhish)", signals.get(0).description());
        assertTrue(signals.get(0).evidence().contains("worse.example/pay"));
    }

    @Test
    void emptyIndexMatchesNothing() {
        ThreatFeedIndex index = ThreatFeedIndex.empty(List.of());

        assertTrue(index.isEmpty());
        assertTrue(index.matches("https://evil.example/login").isEmpty());
        assertTrue(index.signalsForAny(List.of("https://evil.example/login")).isEmpty());
    }

    @Test
    void unparsableUrlMatchesNothing() {
        ThreatFeedIndex index = index(Set.of(), snapshot(FeedSource.OPENPHISH, "evil.example/login"));

        assertTrue(index.matches("not a url at all").isEmpty());
        assertTrue(index.matches("").isEmpty());
    }
}
