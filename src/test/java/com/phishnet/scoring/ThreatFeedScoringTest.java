package com.phishnet.scoring;

import com.phishnet.analyzer.UrlAnalyzer;
import com.phishnet.batch.UrlScanner;
import com.phishnet.feeds.FeedEntries;
import com.phishnet.feeds.FeedSnapshot;
import com.phishnet.feeds.FeedSource;
import com.phishnet.feeds.ThreatFeedIndex;
import com.phishnet.model.DomainAgeResult;
import com.phishnet.model.PhishNetConfig;
import com.phishnet.model.RiskLevel;
import com.phishnet.model.RiskScore;
import com.phishnet.model.Signal;
import com.phishnet.model.UrlAnalysisResult;
import com.phishnet.util.ConfigLoader;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Feed matches as scoring signals: weighted from the YAML config, and added to (not replacing) everything else. */
class ThreatFeedScoringTest {

    private static final PhishNetConfig CONFIG = ConfigLoader.loadDefault();
    private static final RiskScorer SCORER = new RiskScorer(CONFIG);

    private static ThreatFeedIndex feeds(String... keys) {
        return new ThreatFeedIndex(
                List.of(new FeedSnapshot(FeedSource.OPENPHISH, FeedEntries.ofKeys(List.of(keys)),
                        Instant.parse("2026-11-10T11:00:00Z"))),
                List.of(), Set.of());
    }

    private static Signal urlSignal() {
        return feeds("evil.example/login").signalsFor("https://evil.example/login").get(0);
    }

    private static Signal domainSignal() {
        return feeds("evil.example/login").signalsFor("https://evil.example/").get(0);
    }

    private static PhishNetConfig yaml(String text) {
        return ConfigLoader.load(new ByteArrayInputStream(text.getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void bundledConfigWeighsFeedMatchesHeavily() {
        assertEquals(70, CONFIG.scoring().weightOf(RiskScorer.KNOWN_PHISHING_URL));
        assertEquals(40, CONFIG.scoring().weightOf(RiskScorer.KNOWN_PHISHING_DOMAIN));
    }

    @Test
    void listedUrlAloneIsHighRisk() {
        RiskScore score = SCORER.score(List.of(urlSignal()));

        assertEquals(70, score.score());
        assertEquals(RiskLevel.HIGH, score.level());
        assertEquals(List.of(urlSignal()), score.signals());
    }

    @Test
    void listedDomainAloneIsMediumRisk() {
        RiskScore score = SCORER.score(List.of(domainSignal()));

        assertEquals(40, score.score());
        assertEquals(RiskLevel.MEDIUM, score.level());
    }

    @Test
    void feedSignalAddsToTheHeuristicSignals() {
        UrlAnalysisResult analysis = new UrlAnalyzer(CONFIG).analyze("http://paypa1-login.xyz/verify");
        int heuristicScore = SCORER.score(analysis.signals()).score();
        List<Signal> combined = new ArrayList<>(analysis.signals());
        combined.add(domainSignal());

        RiskScore score = SCORER.score(combined);

        assertFalse(analysis.signals().isEmpty());
        assertEquals(Math.min(100, heuristicScore + 40), score.score());
        assertTrue(score.signals().containsAll(analysis.signals()));
        assertTrue(score.signals().contains(domainSignal()));
    }

    @Test
    void feedSignalCombinesWithDomainAge() {
        DomainAgeResult newDomain = DomainAgeResult.known("evil.example", LocalDate.of(2026, 11, 1), 9,
                "whois.example");

        RiskScore score = SCORER.score(List.of(domainSignal()), newDomain);

        assertEquals(40 + CONFIG.scoring().weightOf(RiskScorer.DOMAIN_AGE_NEW), score.score());
        assertEquals(RiskLevel.HIGH, score.level());
        assertTrue(score.signals().stream().anyMatch(s -> s.id().equals(RiskScorer.DOMAIN_AGE_NEW)));
        assertTrue(score.signals().contains(domainSignal()));
    }

    @Test
    void scoreStaysCappedAt100() {
        List<Signal> signals = List.of(urlSignal(), urlSignal(), domainSignal());

        assertEquals(100, SCORER.score(signals).score());
    }

    @Test
    void yamlWeightOverridesTheDefault() {
        PhishNetConfig config = yaml("""
                scoring:
                  weights:
                    knownPhishingUrl: 25
                    knownPhishingDomain: 5
                """);

        RiskScorer scorer = new RiskScorer(config);

        assertEquals(25, scorer.score(List.of(urlSignal())).score());
        assertEquals(5, scorer.score(List.of(domainSignal())).score());
    }

    @Test
    void configWrittenBeforeFeedsExistedStillScoresThemHeavily() {
        PhishNetConfig config = yaml("""
                scoring:
                  weights:
                    suspiciousTld: 20
                """);
        RiskScorer scorer = new RiskScorer(config);

        assertEquals(70, scorer.score(List.of(urlSignal())).score());
        assertEquals(40, scorer.score(List.of(domainSignal())).score());
        // Every other unknown signal keeps the usual fallback.
        assertEquals(10, config.scoring().weightOf("someSignalNotInConfig"));
    }

    @Test
    void urlScannerAddsFeedSignalsToItsScore() {
        UrlAnalyzer analyzer = new UrlAnalyzer(CONFIG);
        UrlScanner withFeeds = new UrlScanner(analyzer, UrlScanner.SKIP_DOMAIN_AGE, SCORER,
                feeds("evil.example/login"));
        UrlScanner withoutFeeds = new UrlScanner(analyzer, UrlScanner.SKIP_DOMAIN_AGE, SCORER);

        UrlScanner.Result listed = withFeeds.scan("https://evil.example/login");
        UrlScanner.Result unlisted = withoutFeeds.scan("https://evil.example/login");

        assertEquals(Math.min(100, unlisted.score().score() + 70), listed.score().score());
        assertTrue(listed.score().signals().stream().anyMatch(s -> s.id().equals(RiskScorer.KNOWN_PHISHING_URL)));
        assertTrue(unlisted.score().signals().stream().noneMatch(s -> s.id().equals(RiskScorer.KNOWN_PHISHING_URL)));
        // The analysis itself is untouched, so ML features and history components are unchanged.
        assertEquals(unlisted.analysis().signals(), listed.analysis().signals());
    }
}
