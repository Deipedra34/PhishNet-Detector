package com.phishnet.api;

import com.phishnet.analyzer.DomainAgeChecker;
import com.phishnet.analyzer.EmailAnalyzer;
import com.phishnet.analyzer.UrlAnalyzer;
import com.phishnet.analyzer.WhoisClient;
import com.phishnet.cli.ReportFormatter;
import com.phishnet.model.DomainAgeResult;
import com.phishnet.model.EmailAnalysisResult;
import com.phishnet.model.PhishNetConfig;
import com.phishnet.model.RiskScore;
import com.phishnet.model.UrlAnalysisResult;
import com.phishnet.scoring.RiskScorer;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Runs one URL or email through the same analyzers and {@link RiskScorer} the
 * CLI uses, and returns the result as a JSON-ready map. Holds no per-request
 * state, so a single instance is shared by every request the API server handles.
 *
 * Unlike the CLI, API scans are not written to the scan-history CSV or an HTML
 * report - the server stays free of filesystem side effects.
 */
public final class ScanService {

    private final UrlAnalyzer urlAnalyzer;
    private final EmailAnalyzer emailAnalyzer;
    private final RiskScorer scorer;
    private final WhoisClient whoisClient;

    /**
     * @param whoisClient WHOIS transport for URL scans' domain-age lookup, or {@code null}
     *                    to skip domain age entirely (the API equivalent of {@code --no-whois})
     */
    public ScanService(PhishNetConfig config, WhoisClient whoisClient) {
        this.urlAnalyzer = new UrlAnalyzer(config);
        this.emailAnalyzer = new EmailAnalyzer(config, urlAnalyzer);
        this.scorer = new RiskScorer(config);
        this.whoisClient = whoisClient;
    }

    public Map<String, Object> scanUrl(String url) {
        UrlAnalysisResult result = urlAnalyzer.analyze(url);
        // A fresh checker per request: DomainAgeChecker's per-run caches (results, and
        // servers that failed once) aren't thread-safe and would otherwise live, and go
        // stale, for as long as the server runs.
        DomainAgeResult domainAge = whoisClient == null
                ? DomainAgeResult.skipped()
                : new DomainAgeChecker(whoisClient).check(result.components());
        RiskScore score = scorer.score(result.signals(), domainAge);

        Map<String, Object> root = withType(ReportFormatter.toMap(url, score), "URL");
        root.put("domainAge", domainAgeMap(domainAge));
        return root;
    }

    /** Analyzes a raw .eml message. Doesn't close the stream. */
    public Map<String, Object> scanEmail(String label, InputStream eml) {
        EmailAnalysisResult result = emailAnalyzer.analyze(eml);
        RiskScore score = scorer.score(result.allSignals());

        Map<String, Object> email = new LinkedHashMap<>();
        email.put("from", result.senderAddress());
        email.put("displayName", result.displayName());
        email.put("replyTo", result.replyToAddress());
        email.put("subject", result.subject());
        List<String> links = new ArrayList<>();
        for (UrlAnalysisResult link : result.linkResults()) {
            links.add(link.components().rawUrl());
        }
        email.put("links", links);

        Map<String, Object> root = withType(ReportFormatter.toMap(label, score), "EMAIL");
        root.put("email", email);
        return root;
    }

    /** Re-inserts "type" right after "target" so it reads naturally at the top of the response. */
    private static Map<String, Object> withType(Map<String, Object> base, String type) {
        Map<String, Object> root = new LinkedHashMap<>();
        root.put("target", base.remove("target"));
        root.put("type", type);
        root.putAll(base);
        return root;
    }

    private static Map<String, Object> domainAgeMap(DomainAgeResult domainAge) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("status", domainAge.status().name());
        switch (domainAge.status()) {
            case KNOWN -> {
                map.put("domain", domainAge.domain());
                map.put("creationDate", domainAge.creationDate().toString());
                map.put("ageDays", domainAge.ageDays());
                map.put("age", domainAge.formatAge());
                map.put("whoisServer", domainAge.whoisServer());
            }
            case UNKNOWN -> {
                map.put("domain", domainAge.domain());
                map.put("reason", domainAge.reason());
            }
            case SKIPPED -> {
                // Nothing was looked up - status alone says so.
            }
        }
        return map;
    }
}
