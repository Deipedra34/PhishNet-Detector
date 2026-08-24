package com.phishnet.cli;

import com.phishnet.model.EmailAnalysisResult;
import com.phishnet.model.RiskLevel;
import com.phishnet.model.RiskScore;
import com.phishnet.model.Signal;
import com.phishnet.model.UrlAnalysisResult;
import com.phishnet.model.UrlComponents;
import com.phishnet.util.AnsiColor;

import java.io.PrintStream;

/**
 * The one place all CLI text output goes through. Analyzers and the scorer
 * just hand back data (UrlAnalysisResult, EmailAnalysisResult, RiskScore);
 * this class decides what to actually print, based on the OutputLevel and
 * whether colors are enabled.
 *
 * QUIET always prints exactly one plain line and never uses color, no
 * matter what colorEnabled was passed in.
 */
public final class Reporter {

    private final PrintStream out;
    private final OutputLevel level;
    private final boolean colorEnabled;

    public Reporter(PrintStream out, OutputLevel level, boolean colorEnabled) {
        this.out = out;
        this.level = level;
        this.colorEnabled = colorEnabled && level != OutputLevel.QUIET;
    }

    public OutputLevel level() {
        return level;
    }

    public void reportUrl(String target, UrlAnalysisResult result, RiskScore score) {
        if (level == OutputLevel.QUIET) {
            printQuietLine(target, score);
            return;
        }
        printSummary(target, score);
        if (level == OutputLevel.VERBOSE) {
            printUrlDetails(result.components());
        }
    }

    public void reportEmail(String target, EmailAnalysisResult result, RiskScore score) {
        if (level == OutputLevel.QUIET) {
            printQuietLine(target, score);
            return;
        }
        printSummary(target, score);
        if (level == OutputLevel.VERBOSE) {
            printEmailDetails(result);
        }
    }

    public void reportBatchEntry(AnalysisEntry entry) {
        if (level == OutputLevel.QUIET) {
            printQuietLine(entry.label(), entry.score());
            return;
        }
        printSummary(entry.label(), entry.score());
        out.println("---");
    }

    public void reportBatchSummary(int total, long high, long medium) {
        if (level == OutputLevel.QUIET) {
            return;
        }
        out.println("Summary: " + total + " URL(s) analyzed - " + high + " high risk, " + medium + " medium risk");
    }

    // --- summary block, shared by NORMAL and VERBOSE ------------------------

    private void printSummary(String target, RiskScore score) {
        out.println("Target: " + target);
        out.println("Risk Score: " + score.score() + "/100 (" + coloredLevel(score.level()) + ")");

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

    private void printUrlDetails(UrlComponents c) {
        out.println("Details:");
        out.println("  scheme=" + c.scheme() + ", host=" + c.host() + ", subdomain=" + c.subdomain()
                + ", domain=" + c.domain() + ", tld=" + c.tld() + ", ip=" + c.isIpHost());
        out.println("  path=" + c.path() + ", query params=" + c.queryParams().size());
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
