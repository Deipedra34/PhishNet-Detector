package com.phishnet.cli;

import com.phishnet.history.HistoryEntry;
import com.phishnet.history.HistoryStats;
import com.phishnet.model.RiskLevel;
import com.phishnet.util.AnsiColor;

import java.io.PrintStream;
import java.nio.file.Path;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Locale;

/**
 * Renders {@code phishnet history} results, following the same conventions as
 * {@link Reporter}: QUIET prints one plain {@code LEVEL SCORE TARGET} line per scan
 * (never colored), NORMAL a table, and VERBOSE the table plus each scan's domain,
 * domain age, email subject, and signals. Risk levels are colored like scan output.
 *
 * Timestamps are shown in {@code zone} (the system time zone in real use).
 */
final class HistoryReporter {

    private static final DateTimeFormatter MINUTES = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm", Locale.ROOT);
    private static final DateTimeFormatter SECONDS = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss", Locale.ROOT);

    private final PrintStream out;
    private final OutputLevel level;
    private final boolean colorEnabled;
    private final ZoneId zone;

    HistoryReporter(PrintStream out, OutputLevel level, boolean colorEnabled, ZoneId zone) {
        this.out = out;
        this.level = level;
        this.colorEnabled = colorEnabled && level != OutputLevel.QUIET;
        this.zone = zone;
    }

    /**
     * Prints {@code entries} (newest first). {@code emptyMessage} is shown instead of
     * an empty table, except in QUIET mode, which prints nothing at all for no results.
     */
    void printEntries(List<HistoryEntry> entries, Path database, String emptyMessage) {
        if (level == OutputLevel.QUIET) {
            for (HistoryEntry entry : entries) {
                out.println(entry.riskLevel().name() + " " + entry.riskScore() + " " + entry.target());
            }
            return;
        }
        if (entries.isEmpty()) {
            out.println(emptyMessage + " (database: " + database + ")");
            return;
        }

        DateTimeFormatter timeFormat = level == OutputLevel.VERBOSE ? SECONDS : MINUTES;
        int idWidth = "ID".length();
        int timeWidth = "TIME".length();
        for (HistoryEntry entry : entries) {
            idWidth = Math.max(idWidth, Long.toString(entry.id()).length());
            timeWidth = Math.max(timeWidth, formatTime(entry.timestamp(), timeFormat).length());
        }

        out.println(padLeft("ID", idWidth) + "  " + padRight("TIME", timeWidth) + "  "
                + padRight("TYPE", 5) + "  " + padLeft("SCORE", 5) + "  " + padRight("RISK", 6) + "  TARGET");
        for (HistoryEntry entry : entries) {
            // Pad before coloring so the escape codes don't throw the column widths off.
            String risk = padRight(entry.riskLevel().name(), 6);
            out.println(padLeft(Long.toString(entry.id()), idWidth) + "  "
                    + padRight(formatTime(entry.timestamp(), timeFormat), timeWidth) + "  "
                    + padRight(entry.type().name(), 5) + "  "
                    + padLeft(Integer.toString(entry.riskScore()), 5) + "  "
                    + coloredLevel(entry.riskLevel(), risk) + "  "
                    + entry.target());
            if (level == OutputLevel.VERBOSE) {
                printDetails(entry, idWidth + 2);
            }
        }
        out.println();
        out.println(entries.size() + " scan(s) shown (database: " + database + ")");
    }

    void printStats(HistoryStats stats, Path database) {
        if (level == OutputLevel.QUIET) {
            out.println("total=" + stats.total()
                    + " high=" + stats.byRiskLevel().get(RiskLevel.HIGH)
                    + " medium=" + stats.byRiskLevel().get(RiskLevel.MEDIUM)
                    + " low=" + stats.byRiskLevel().get(RiskLevel.LOW)
                    + " url=" + stats.byType().get(HistoryWriter.TargetType.URL)
                    + " email=" + stats.byType().get(HistoryWriter.TargetType.EMAIL));
            return;
        }
        if (stats.total() == 0) {
            out.println("No scans recorded yet (database: " + database + ")");
            return;
        }

        out.println("Total scans: " + stats.total() + " (" + formatTime(stats.firstScan(), MINUTES)
                + " to " + formatTime(stats.lastScan(), MINUTES) + ")");
        out.println("Database: " + database);

        out.println();
        out.println("By risk level:");
        int countWidth = Long.toString(stats.total()).length();
        for (RiskLevel riskLevel : new RiskLevel[] {RiskLevel.HIGH, RiskLevel.MEDIUM, RiskLevel.LOW}) {
            long count = stats.byRiskLevel().get(riskLevel);
            double percent = 100.0 * count / stats.total();
            out.println("  " + coloredLevel(riskLevel, padRight(riskLevel.name(), 6)) + "  "
                    + padLeft(Long.toString(count), countWidth) + "  "
                    + padLeft(String.format(Locale.ROOT, "%.1f%%", percent), 6));
        }

        out.println();
        out.println("By type:");
        for (HistoryWriter.TargetType type : HistoryWriter.TargetType.values()) {
            out.println("  " + padRight(type.name(), 6) + "  "
                    + padLeft(Long.toString(stats.byType().get(type)), countWidth));
        }

        out.println();
        out.println("Most frequently flagged domains (MEDIUM/HIGH risk):");
        if (stats.topFlaggedDomains().isEmpty()) {
            out.println("  (none)");
            return;
        }
        int domainWidth = 0;
        for (HistoryStats.DomainCount domain : stats.topFlaggedDomains()) {
            domainWidth = Math.max(domainWidth, domain.domain().length());
        }
        int rank = 1;
        int rankWidth = Integer.toString(stats.topFlaggedDomains().size()).length();
        for (HistoryStats.DomainCount domain : stats.topFlaggedDomains()) {
            out.println("  " + padLeft(Integer.toString(rank++), rankWidth) + ". "
                    + padRight(domain.domain(), domainWidth) + "  " + domain.count());
        }
    }

    private void printDetails(HistoryEntry entry, int indent) {
        String pad = " ".repeat(indent);
        if (entry.domain() != null) {
            String age = entry.domainAgeDays() == null ? "" : ", domain age " + entry.domainAgeDays() + " days";
            out.println(pad + "Domain: " + entry.domain() + age);
        }
        if (entry.subject() != null) {
            out.println(pad + "Subject: " + entry.subject());
        }
        if (entry.reasons().isEmpty()) {
            out.println(pad + "Signals: none");
            return;
        }
        out.println(pad + "Signals:");
        for (HistoryEntry.Reason reason : entry.reasons()) {
            out.println(pad + "  - [" + reason.id() + "] " + reason.description());
        }
    }

    private String formatTime(Instant instant, DateTimeFormatter format) {
        return format.format(instant.atZone(zone));
    }

    private String coloredLevel(RiskLevel riskLevel, String text) {
        // Color only the level name, not the padding after it.
        String name = riskLevel.name();
        return AnsiColor.apply(name, colorEnabled, AnsiColor.BOLD, colorFor(riskLevel))
                + text.substring(name.length());
    }

    private static AnsiColor colorFor(RiskLevel riskLevel) {
        switch (riskLevel) {
            case HIGH:
                return AnsiColor.RED;
            case MEDIUM:
                return AnsiColor.YELLOW;
            case LOW:
            default:
                return AnsiColor.GREEN;
        }
    }

    private static String padRight(String text, int width) {
        return text.length() >= width ? text : text + " ".repeat(width - text.length());
    }

    private static String padLeft(String text, int width) {
        return text.length() >= width ? text : " ".repeat(width - text.length()) + text;
    }
}
