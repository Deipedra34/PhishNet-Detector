package com.phishnet.cli;

import com.phishnet.history.HistoryEntry;
import com.phishnet.history.HistoryStats;
import com.phishnet.i18n.Messages;
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
    private final Messages msg = Messages.current();

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
            out.println(msg.get("history.withDatabase", emptyMessage, database));
            return;
        }

        DateTimeFormatter timeFormat = level == OutputLevel.VERBOSE ? SECONDS : MINUTES;
        String idHeader = msg.get("history.column.id");
        String timeHeader = msg.get("history.column.time");
        String typeHeader = msg.get("history.column.type");
        String scoreHeader = msg.get("history.column.score");
        String riskHeader = msg.get("history.column.risk");
        int idWidth = idHeader.length();
        int timeWidth = timeHeader.length();
        // Never narrower than the English columns, so the English table keeps its layout.
        int typeWidth = Math.max(5, Math.max(typeHeader.length(), typeLabelWidth()));
        int scoreWidth = Math.max(5, scoreHeader.length());
        int riskWidth = Math.max(6, Math.max(riskHeader.length(), riskLabelWidth()));
        for (HistoryEntry entry : entries) {
            idWidth = Math.max(idWidth, Long.toString(entry.id()).length());
            timeWidth = Math.max(timeWidth, formatTime(entry.timestamp(), timeFormat).length());
        }

        out.println(padLeft(idHeader, idWidth) + "  " + padRight(timeHeader, timeWidth) + "  "
                + padRight(typeHeader, typeWidth) + "  " + padLeft(scoreHeader, scoreWidth) + "  "
                + padRight(riskHeader, riskWidth) + "  " + msg.get("history.column.target"));
        for (HistoryEntry entry : entries) {
            // Pad before coloring so the escape codes don't throw the column widths off.
            String risk = padRight(riskLabel(entry.riskLevel()), riskWidth);
            out.println(padLeft(Long.toString(entry.id()), idWidth) + "  "
                    + padRight(formatTime(entry.timestamp(), timeFormat), timeWidth) + "  "
                    + padRight(typeLabel(entry.type()), typeWidth) + "  "
                    + padLeft(Integer.toString(entry.riskScore()), scoreWidth) + "  "
                    + coloredLevel(entry.riskLevel(), risk) + "  "
                    + entry.target());
            if (level == OutputLevel.VERBOSE) {
                printDetails(entry, idWidth + 2);
            }
        }
        out.println();
        out.println(msg.get("history.shown", entries.size(), database));
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
            out.println(msg.get("history.withDatabase", msg.get("history.noScans"), database));
            return;
        }

        out.println(msg.get("history.stats.total", stats.total(), formatTime(stats.firstScan(), MINUTES),
                formatTime(stats.lastScan(), MINUTES)));
        out.println(msg.get("history.stats.database", database));

        out.println();
        out.println(msg.get("history.stats.byRisk"));
        int countWidth = Long.toString(stats.total()).length();
        int labelWidth = Math.max(6, riskLabelWidth());
        for (RiskLevel riskLevel : new RiskLevel[] {RiskLevel.HIGH, RiskLevel.MEDIUM, RiskLevel.LOW}) {
            long count = stats.byRiskLevel().get(riskLevel);
            double percent = 100.0 * count / stats.total();
            out.println("  " + coloredLevel(riskLevel, padRight(riskLabel(riskLevel), labelWidth)) + "  "
                    + padLeft(Long.toString(count), countWidth) + "  "
                    + padLeft(String.format(Locale.ROOT, "%.1f%%", percent), 6));
        }

        out.println();
        out.println(msg.get("history.stats.byType"));
        int typeWidth = Math.max(6, typeLabelWidth());
        for (HistoryWriter.TargetType type : HistoryWriter.TargetType.values()) {
            out.println("  " + padRight(typeLabel(type), typeWidth) + "  "
                    + padLeft(Long.toString(stats.byType().get(type)), countWidth));
        }

        out.println();
        out.println(msg.get("history.stats.topDomains"));
        if (stats.topFlaggedDomains().isEmpty()) {
            out.println("  " + msg.get("common.none"));
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
            out.println(pad + (entry.domainAgeDays() == null
                    ? msg.get("history.detail.domain", entry.domain())
                    : msg.get("history.detail.domainWithAge", entry.domain(), entry.domainAgeDays())));
        }
        if (entry.subject() != null) {
            out.println(pad + msg.get("report.email.subject", entry.subject()));
        }
        if (entry.reasons().isEmpty()) {
            out.println(pad + msg.get("report.signals.none"));
            return;
        }
        out.println(pad + msg.get("report.signals"));
        for (HistoryEntry.Reason reason : entry.reasons()) {
            out.println(pad + "  - [" + reason.id() + "] " + reason.description());
        }
    }

    private String formatTime(Instant instant, DateTimeFormatter format) {
        return format.format(instant.atZone(zone));
    }

    private String coloredLevel(RiskLevel riskLevel, String text) {
        // Color only the level name, not the padding after it.
        String name = riskLabel(riskLevel);
        return AnsiColor.apply(name, colorEnabled, AnsiColor.BOLD, colorFor(riskLevel))
                + text.substring(name.length());
    }

    private String riskLabel(RiskLevel riskLevel) {
        return msg.get("risk." + riskLevel.name());
    }

    private int riskLabelWidth() {
        int width = 0;
        for (RiskLevel riskLevel : RiskLevel.values()) {
            width = Math.max(width, riskLabel(riskLevel).length());
        }
        return width;
    }

    private String typeLabel(HistoryWriter.TargetType type) {
        return msg.get("type." + type.name());
    }

    private int typeLabelWidth() {
        int width = 0;
        for (HistoryWriter.TargetType type : HistoryWriter.TargetType.values()) {
            width = Math.max(width, typeLabel(type).length());
        }
        return width;
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
