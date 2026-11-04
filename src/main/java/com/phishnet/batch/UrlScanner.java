package com.phishnet.batch;

import com.phishnet.analyzer.UrlAnalyzer;
import com.phishnet.model.DomainAgeResult;
import com.phishnet.model.RiskScore;
import com.phishnet.model.UrlAnalysisResult;
import com.phishnet.scoring.RiskScorer;

import java.util.Objects;

/**
 * The URL scan pipeline shared by {@code --batch} and {@code phishnet queue worker}:
 * analyze the URL, look up its domain age, score the result. Safe to call from many
 * threads at once - the analyzer and scorer hold only read-only configuration, and
 * the domain-age lookup is supplied by the caller (who decides how it is cached).
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

    public UrlScanner(UrlAnalyzer analyzer, DomainAgeLookup domainAge, RiskScorer scorer) {
        this.analyzer = Objects.requireNonNull(analyzer);
        this.domainAge = Objects.requireNonNull(domainAge);
        this.scorer = Objects.requireNonNull(scorer);
    }

    public Result scan(String url) {
        UrlAnalysisResult analysis = analyzer.analyze(url);
        DomainAgeResult age = domainAge.lookup(analysis);
        return new Result(url, analysis, age, scorer.score(analysis.signals(), age));
    }
}
