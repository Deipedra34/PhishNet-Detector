package com.phishnet.cli;

import com.phishnet.feeds.FeedStatus;
import com.phishnet.ml.MlPrediction;
import com.phishnet.model.DomainAgeResult;
import com.phishnet.model.EmailAnalysisResult;
import com.phishnet.model.RiskLevel;
import com.phishnet.model.RiskScore;
import com.phishnet.model.Signal;
import com.phishnet.model.UrlAnalysisResult;
import com.phishnet.model.UrlComponents;
import com.phishnet.util.AnsiColor;

import java.io.PrintStream;
import java.util.List;

/**
 * The one place all CLI text output goes through. Analyzers and the scorer
 * just hand back data (UrlAnalysisResult, EmailAnalysisResult, RiskScore);
 * this class decides what to actually print, based on the OutputLevel and
 * whether colors are enabled.
 *
 * QUIET always prints exactly one plain line and never uses color, no
 * matter what colorEnabled was passed in.
 *
 * Threat feed matches are ordinary signals, so they show up in NORMAL and
 * VERBOSE like any other ("Known phishing URL (OpenPhish)", plus the matched
 * entry in VERBOSE). VERBOSE also lists each feed's status, so "not listed"
 * can be told apart from "no feed data".
 */
public final class Reporter {

    private final PrintStream out;
    private final OutputLevel level;
    private final boolean colorEnabled;
    private final List<FeedStatus> feedStatuses;

    public Reporter(PrintStream out, OutputLevel level, boolean colorEnabled) {
        this(out, level, colorEnabled, List.of());
    }

    /** @param feedStatuses the threat feeds' state for this run, listed in VERBOSE output */
    public Reporter(PrintStream out, OutputLevel level, boolean colorEnabled, List<FeedStatus> feedStatuses) {
        this.out = out;
        this.level = level;
        this.colorEnabled = colorEnabled && level != OutputLevel.QUIET;
        this.feedStatuses = List.copyOf(feedStatuses);
    }

    public OutputLevel level() {
        return level;
    }

    public void reportUrl(String target, UrlAnalysisResult result, RiskScore score) {
        reportUrl(target, result, score, DomainAgeResult.skipped());
    }

    public void reportUrl(String target, UrlAnalysisResult result, RiskScore score, DomainAgeResult domainAge) {
        reportUrl(target, result, score, domainAge, null);
    }

    /** @param ml the ML layer's prediction, or {@code null} when ML is off or produced none */
    public void reportUrl(String target, UrlAnalysisResult result, RiskScore score, DomainAgeResult domainAge,
                          MlPrediction ml) {
        if (level == OutputLevel.QUIET) {
            printQuietLine(target, score);
            return;
        }
        printSummary(target, score, domainAge, ml);
        if (level == OutputLevel.VERBOSE) {
            printUrlDetails(result.components(), ml);
            printThreatFeeds();
        }
    }

    public void reportEmail(String target, EmailAnalysisResult result, RiskScore score) {
        if (level == OutputLevel.QUIET) {
            printQuietLine(target, score);
            return;
        }
        printSummary(target, score, DomainAgeResult.skipped(), null);
        if (level == OutputLevel.VERBOSE) {
            printEmailDetails(result);
            printThreatFeeds();
        }
    }

    public void reportBatchEntry(AnalysisEntry entry) {
        reportBatchEntry(entry, null);
    }

    /** @param ml the ML layer's prediction for this entry, or {@code null} */
    public void reportBatchEntry(AnalysisEntry entry, MlPrediction ml) {
        if (level == OutputLevel.QUIET) {
            printQuietLine(entry.label(), entry.score());
            return;
        }
        printSummary(entry.label(), entry.score(), entry.domainAge(), ml);
        out.println("---");
    }

    public void reportBatchSummary(int total, long high, long medium) {
        if (level == OutputLevel.QUIET) {
            return;
        }
        out.println("Summary: " + total + " URL(s) analyzed - " + high + " high risk, " + medium + " medium risk");
        if (level == OutputLevel.VERBOSE) {
            printThreatFeeds();
        }
    }

    /**
     * "Threat Feeds:" and one line per feed. Nothing when feeds are off for the
     * run (--no-threat-feeds), the same way a skipped WHOIS lookup prints nothing.
     */
    private void printThreatFeeds() {
        if (feedStatuses.stream().allMatch(status -> status.state() == FeedStatus.State.OFF)) {
            return;
        }
        out.println("Threat Feeds:");
        for (FeedStatus status : feedStatuses) {
            out.println("  " + status.source().displayName() + ": " + status.describe());
        }
    }

    // --- summary block, shared by NORMAL and VERBOSE ------------------------

    private void printSummary(String target, RiskScore score, DomainAgeResult domainAge, MlPrediction ml) {
        out.println("Target: " + target);
        out.println("Risk Score: " + score.score() + "/100 (" + coloredLevel(score.level()) + ")");
        printDomainAge(domainAge);
        printMlConfidence(ml);

        if (score.signals().isEmpty()) {
            out.println(AnsiColor.apply("✓", colorEnabled, AnsiColor.GREEN) + " No phishing indicators detected");
        } else {
            out.println("Signals:");
            String symbol = symbolFor(score.level());
            AnsiColor color = colorFor(score.level());
            for (Signal signal : score.signals()) {
                StringBuilder line = new StringBuilder("  ")
                        .append(AnsiColor.apply(symbol, colorEnabled, color))
                        .append(" [").append(signal.id()).append("] ").append(signal.description());
                if (level == OutputLevel.VERBOSE && !signal.evidence().isEmpty()) {
                    line.append(" (").append(signal.evidence()).append(")");
                }
                out.println(line);
            }
        }
        out.println("Recommendation: " + score.recommendation());
    }

    /**
     * "Domain Age: 3 months" (NORMAL) or with days/creation date/server appended
     * (VERBOSE). A failed lookup prints "unknown" (plus the reason in VERBOSE);
     * a skipped one (--no-whois, IP host) prints nothing.
     */
    private void printDomainAge(DomainAgeResult domainAge) {
        if (domainAge == null || domainAge.isSkipped()) {
            return;
        }
        StringBuilder line = new StringBuilder("Domain Age: ").append(domainAge.formatAge());
        if (level == OutputLevel.VERBOSE) {
            if (domainAge.isKnown()) {
                line.append(" (").append(domainAge.ageDays()).append(" days, created ")
                        .append(domainAge.creationDate()).append(", via ").append(domainAge.whoisServer()).append(")");
            } else if (!domainAge.reason().isEmpty()) {
                line.append(" (").append(domainAge.reason()).append(")");
            }
        }
        out.println(line);
    }

    /**
     * "ML Confidence: 73% phishing-like (experimental)" - printed right under the
     * rule-based score, which stays the authoritative one. Nothing when ML is off.
     */
    private void printMlConfidence(MlPrediction ml) {
        if (ml == null) {
            return;
        }
        out.println("ML Confidence: " + ml.displayPercent() + " phishing-like (experimental)");
    }

    private void printUrlDetails(UrlComponents c, MlPrediction ml) {
        out.println("Details:");
        out.println("  scheme=" + c.scheme() + ", host=" + c.host() + ", subdomain=" + c.subdomain()
                + ", domain=" + c.domain() + ", tld=" + c.tld() + ", ip=" + c.isIpHost());
        out.println("  path=" + c.path() + ", query params=" + c.queryParams().size());
        if (ml != null) {
            out.println("  ml features: " + ml.features());
        }
    }

    private void printEmailDetails(EmailAnalysisResult result) {
        out.println("Details:");
        out.println("  From: " + result.displayName() + " <" + result.senderAddress() + ">");
        out.println("  Reply-To: " + (result.replyToAddress().isEmpty() ? "(none)" : result.replyToAddress()));
        out.println("  Subject: " + result.subject());
        out.println("  Links inspected (" + result.linkResults().size() + "):");
        for (UrlAnalysisResult link : result.linkResults()) {
            out.println("    - " + link.components().rawUrl());
        }
    }

    private void printQuietLine(String target, RiskScore score) {
        out.println(score.level().name() + " " + score.score() + " " + target);
    }

    private String coloredLevel(RiskLevel level) {
        return AnsiColor.apply(level.name(), colorEnabled, AnsiColor.BOLD, colorFor(level));
    }

    private static AnsiColor colorFor(RiskLevel level) {
        switch (level) {
            case HIGH:
                return AnsiColor.RED;
            case MEDIUM:
                return AnsiColor.YELLOW;
            case LOW:
            default:
                return AnsiColor.GREEN;
        }
    }

    private static String symbolFor(RiskLevel level) {
        return level == RiskLevel.HIGH ? "✗" : "⚠";
    }
}
