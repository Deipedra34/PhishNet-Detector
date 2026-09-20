package com.phishnet.cli;

import com.phishnet.model.RiskLevel;
import com.phishnet.model.RiskScore;
import com.phishnet.model.Signal;

import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;

/**
 * Writes a single, self-contained HTML file summarizing a scan run's results:
 * a header, LOW/MEDIUM/HIGH summary stats, and a results table sorted with
 * the highest risk first.
 *
 * <p>Kept separate from {@link Reporter} (console output) and {@link HistoryWriter}
 * (CSV log) - three independent output concerns that happen to render the same
 * {@link AnalysisEntry} data. Like {@link HistoryWriter}, a failure to write the
 * report is reported to stderr and never aborts the scan.
 *
 * <p>All CSS is inlined and there is no JavaScript or external asset reference,
 * so the file opens correctly offline in any browser.
 */
public final class HtmlReportWriter {

    private final Path file;
    private final boolean enabled;
    private final String toolVersion;
    private final PrintStream err;

    /**
     * @param file        destination HTML file (parent directories are created if missing)
     * @param enabled     when false, {@link #write} does nothing (used when {@code --html-report} is absent)
     * @param toolVersion version string shown in the report header (e.g. {@code "1.0.0"})
     * @param err         stream that I/O warnings are printed to
     */
    public HtmlReportWriter(Path file, boolean enabled, String toolVersion, PrintStream err) {
        this.file = file;
        this.enabled = enabled;
        this.toolVersion = toolVersion;
        this.err = err;
    }

    /**
     * Renders and writes the report for one completed run - called once, whether
     * the run was a single {@code --url}/{@code --email} scan (a one-entry list)
     * or a whole {@code --batch} (every item scanned in that run).
     */
    public void write(List<AnalysisEntry> entries) {
        if (!enabled) {
            return;
        }
        String html = render(entries, Instant.now());
        try {
            Path parent = file.toAbsolutePath().getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            Files.writeString(file, html, StandardCharsets.UTF_8);
        } catch (IOException e) {
            err.println("Warning: could not write HTML report to " + file + ": " + e.getMessage());
        }
    }

    /** Package-visible for direct testing without touching the filesystem. */
    String render(List<AnalysisEntry> entries, Instant timestamp) {
        List<AnalysisEntry> sorted = sortedByRisk(entries);
        StringBuilder html = new StringBuilder();
        html.append("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n");
        html.append(renderHead());
        html.append("</head>\n<body>\n");
        html.append(renderHeader(entries.size(), timestamp));
        html.append(renderSummary(entries));
        html.append(renderTable(sorted));
        html.append("</body>\n</html>\n");
        return html.toString();
    }

    private String renderHead() {
        return "  <meta charset=\"UTF-8\">\n"
                + "  <title>PhishNet Detector Scan Report</title>\n"
                + "  <style>\n" + CSS + "  </style>\n";
    }

    private String renderHeader(int total, Instant timestamp) {
        return "  <header>\n"
                + "    <h1>PhishNet Detector</h1>\n"
                + "    <p class=\"meta\">Version " + escapeHtml(toolVersion)
                + " &middot; Scan run at " + escapeHtml(timestamp.toString())
                + " &middot; " + total + " item" + (total == 1 ? "" : "s") + " scanned</p>\n"
                + "  </header>\n";
    }

    private String renderSummary(List<AnalysisEntry> entries) {
        int total = entries.size();
        long high = entries.stream().filter(e -> e.score().level() == RiskLevel.HIGH).count();
        long medium = entries.stream().filter(e -> e.score().level() == RiskLevel.MEDIUM).count();
        long low = entries.stream().filter(e -> e.score().level() == RiskLevel.LOW).count();

        StringBuilder sb = new StringBuilder();
        sb.append("  <section class=\"summary\">\n");
        sb.append("    <h2>Summary</h2>\n");
        sb.append("    <div class=\"stat-row\">\n");
        sb.append(renderStat("HIGH", high, total, "risk-high"));
        sb.append(renderStat("MEDIUM", medium, total, "risk-medium"));
        sb.append(renderStat("LOW", low, total, "risk-low"));
        sb.append("    </div>\n");
        sb.append("  </section>\n");
        return sb.toString();
    }

    private String renderStat(String label, long count, int total, String cssClass) {
        double pct = total == 0 ? 0.0 : (count * 100.0 / total);
        // Locale.ROOT, not the platform default - a non-English locale (e.g. tr_TR) would
        // otherwise render "20,0%" with a comma decimal separator, breaking the HTML's
        // consistent formatting (and any test asserting on the exact text).
        String pctText = String.format(Locale.ROOT, "%.1f%%", pct);
        return "      <div class=\"stat " + cssClass + "\">\n"
                + "        <div class=\"stat-numbers\"><span class=\"stat-count\">" + count
                + "</span> <span class=\"stat-label\">" + label + "</span> "
                + "<span class=\"stat-pct\">(" + pctText + ")</span></div>\n"
                + "        <div class=\"bar-track\"><div class=\"bar-fill\" style=\"width:" + pctText
                + ";\"></div></div>\n"
                + "      </div>\n";
    }

    private String renderTable(List<AnalysisEntry> sortedEntries) {
        StringBuilder sb = new StringBuilder();
        sb.append("  <section class=\"results\">\n");
        sb.append("    <h2>Results</h2>\n");
        sb.append("    <table>\n");
        sb.append("      <thead><tr><th>Target</th><th>Type</th><th>Score</th>"
                + "<th>Risk</th><th>Signals</th></tr></thead>\n");
        sb.append("      <tbody>\n");
        for (AnalysisEntry entry : sortedEntries) {
            sb.append(renderRow(entry));
        }
        sb.append("      </tbody>\n");
        sb.append("    </table>\n");
        sb.append("  </section>\n");
        return sb.toString();
    }

    private String renderRow(AnalysisEntry entry) {
        RiskScore score = entry.score();
        String cssClass = riskCssClass(score.level());
        StringBuilder sb = new StringBuilder();
        sb.append("        <tr class=\"").append(cssClass).append("\">\n");
        sb.append("          <td class=\"target\">").append(escapeHtml(entry.label())).append("</td>\n");
        sb.append("          <td>").append(entry.type().name()).append("</td>\n");
        sb.append("          <td>").append(score.score()).append("/100</td>\n");
        sb.append("          <td><span class=\"badge ").append(cssClass).append("\">")
                .append(score.level().name()).append("</span></td>\n");
        sb.append("          <td>").append(renderSignals(score.signals())).append("</td>\n");
        sb.append("        </tr>\n");
        return sb.toString();
    }

    private String renderSignals(List<Signal> signals) {
        if (signals.isEmpty()) {
            return "<span class=\"none\">none</span>";
        }
        StringBuilder sb = new StringBuilder("<ul class=\"signals\">");
        for (Signal signal : signals) {
            sb.append("<li><strong>").append(escapeHtml(signal.id())).append("</strong>: ")
                    .append(escapeHtml(signal.description())).append("</li>");
        }
        sb.append("</ul>");
        return sb.toString();
    }

    private static List<AnalysisEntry> sortedByRisk(List<AnalysisEntry> entries) {
        List<AnalysisEntry> sorted = new ArrayList<>(entries);
        sorted.sort(Comparator.comparingInt(e -> riskRank(e.score().level())));
        return sorted;
    }

    /** HIGH first, then MEDIUM, then LOW - the reverse of RiskLevel's natural ordinal order. */
    private static int riskRank(RiskLevel level) {
        switch (level) {
            case HIGH:
                return 0;
            case MEDIUM:
                return 1;
            case LOW:
            default:
                return 2;
        }
    }

    private static String riskCssClass(RiskLevel level) {
        switch (level) {
            case HIGH:
                return "risk-high";
            case MEDIUM:
                return "risk-medium";
            case LOW:
            default:
                return "risk-low";
        }
    }

    /** Escapes text for safe placement in HTML content/attributes - {@code &} first, then the rest. */
    static String escapeHtml(String value) {
        if (value == null) {
            return "";
        }
        return value.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#39;");
    }

    private static final String CSS = """
                body {
                  font-family: -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif;
                  margin: 0;
                  padding: 2rem;
                  background: #f5f6f8;
                  color: #1c1f26;
                }
                header h1 {
                  margin: 0 0 0.25rem 0;
                }
                header .meta {
                  margin: 0 0 1.5rem 0;
                  color: #555;
                  font-size: 0.9rem;
                }
                section {
                  background: #fff;
                  border: 1px solid #dde1e6;
                  border-radius: 6px;
                  padding: 1.25rem 1.5rem;
                  margin-bottom: 1.5rem;
                }
                h2 {
                  margin-top: 0;
                }
                .stat-row {
                  display: flex;
                  gap: 1.5rem;
                  flex-wrap: wrap;
                }
                .stat {
                  flex: 1;
                  min-width: 160px;
                }
                .stat-numbers {
                  font-size: 1.1rem;
                  margin-bottom: 0.35rem;
                }
                .stat-count {
                  font-weight: bold;
                  font-size: 1.4rem;
                }
                .bar-track {
                  background: #e9ecef;
                  border-radius: 4px;
                  height: 10px;
                  overflow: hidden;
                }
                .bar-fill {
                  height: 100%;
                }
                .risk-high .bar-fill, .risk-high .stat-count { background: #c0392b; color: #c0392b; }
                .risk-medium .bar-fill, .risk-medium .stat-count { background: #b7791f; color: #b7791f; }
                .risk-low .bar-fill, .risk-low .stat-count { background: #2e7d32; color: #2e7d32; }
                table {
                  width: 100%;
                  border-collapse: collapse;
                }
                th, td {
                  text-align: left;
                  padding: 0.6rem 0.75rem;
                  border-bottom: 1px solid #eceef1;
                  vertical-align: top;
                }
                th {
                  background: #f0f2f5;
                  font-size: 0.85rem;
                  text-transform: uppercase;
                  letter-spacing: 0.03em;
                }
                td.target {
                  word-break: break-all;
                  max-width: 28rem;
                }
                .badge {
                  display: inline-block;
                  padding: 0.15rem 0.55rem;
                  border-radius: 999px;
                  font-weight: bold;
                  font-size: 0.8rem;
                  color: #fff;
                }
                .badge.risk-high { background: #c0392b; }
                .badge.risk-medium { background: #b7791f; }
                .badge.risk-low { background: #2e7d32; }
                tr.risk-high { background: #fdf1f0; }
                tr.risk-medium { background: #fdf6e9; }
                tr.risk-low { background: #f2f8f2; }
                ul.signals {
                  margin: 0;
                  padding-left: 1.1rem;
                }
                .none {
                  color: #888;
                }
            """;
}
