package com.phishnet.batch;

import com.phishnet.analyzer.UrlAnalyzer;
import com.phishnet.feeds.ThreatFeedIndex;
import com.phishnet.model.DomainAgeResult;
import com.phishnet.model.RiskScore;
import com.phishnet.model.Signal;
import com.phishnet.model.UrlAnalysisResult;
import com.phishnet.scoring.RiskScorer;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * The URL scan pipeline shared by {@code --batch} and {@code phishnet queue worker}:
 * analyze the URL, look up its domain age, check the threat feeds, score the result.
 * Safe to call from many threads at once - the analyzer and scorer hold only read-only
 * configuration, the feed index is immutable, and the domain-age lookup is supplied by
 * the caller (who decides how it is cached).
 */
public final class UrlScanner {

    /** How the domain age is found; {@link #SKIP_DOMAIN_AGE} for {@code --no-whois}. */
    @FunctionalInterface
    public interface DomainAgeLookup {
        DomainAgeResult lookup(UrlAnalysisResult analysis);
    }

    public static final DomainAgeLookup SKIP_DOMAIN_AGE = analysis -> DomainAgeResult.skipped();

    /** Everything one scan produced. */
    public record Result(String url, UrlAnalysisResult analysis, DomainAgeResult domainAge, RiskScore score) {
    }

    private final UrlAnalyzer analyzer;
    private final DomainAgeLookup domainAge;
    private final RiskScorer scorer;
    private final ThreatFeedIndex threatFeeds;

    /** A scanner that doesn't consult any threat feeds. */
    public UrlScanner(UrlAnalyzer analyzer, DomainAgeLookup domainAge, RiskScorer scorer) {
        this(analyzer, domainAge, scorer, ThreatFeedIndex.empty(List.of()));
    }

    /** @param threatFeeds known-phishing feeds whose matches are scored next to the analyzer's signals */
    public UrlScanner(UrlAnalyzer analyzer, DomainAgeLookup domainAge, RiskScorer scorer,
                      ThreatFeedIndex threatFeeds) {
        this.analyzer = Objects.requireNonNull(analyzer);
        this.domainAge = Objects.requireNonNull(domainAge);
        this.scorer = Objects.requireNonNull(scorer);
        this.threatFeeds = Objects.requireNonNull(threatFeeds);
    }

    public Result scan(String url) {
        UrlAnalysisResult analysis = analyzer.analyze(url);
        DomainAgeResult age = domainAge.lookup(analysis);
        return new Result(url, analysis, age, scorer.score(withFeedSignals(analysis.signals(), url), age));
    }

    /** {@code signals} plus any threat feed signal for {@code url}. */
    private List<Signal> withFeedSignals(List<Signal> signals, String url) {
        List<Signal> feedSignals = threatFeeds.signalsFor(url);
        if (feedSignals.isEmpty()) {
            return signals;
        }
        List<Signal> all = new ArrayList<>(signals);
        all.addAll(feedSignals);
        return all;
    }
}
