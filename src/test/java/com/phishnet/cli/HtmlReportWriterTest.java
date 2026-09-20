package com.phishnet.cli;

import com.phishnet.model.RiskLevel;
import com.phishnet.model.RiskScore;
import com.phishnet.model.Signal;
import com.phishnet.model.SignalCategory;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class HtmlReportWriterTest {

    private final ByteArrayOutputStream errBytes = new ByteArrayOutputStream();
    private final PrintStream err = new PrintStream(errBytes, true, StandardCharsets.UTF_8);

    private static RiskScore score(int value, RiskLevel level, String... signalIds) {
        List<Signal> signals = java.util.Arrays.stream(signalIds)
                .map(id -> new Signal(id, SignalCategory.URL, id + " description"))
                .toList();
        return new RiskScore(value, level, signals, "recommendation text");
    }

    private static int countOccurrences(String haystack, String needle) {
        Matcher m = Pattern.compile(Pattern.quote(needle)).matcher(haystack);
        int count = 0;
        while (m.find()) {
            count++;
        }
        return count;
    }

    @Test
    void writesReportContainingOneRowPerEntry(@TempDir Path dir) {
        Path file = dir.resolve("report.html");
        HtmlReportWriter writer = new HtmlReportWriter(file, true, "1.0.0", err);

        writer.write(List.of(
                new AnalysisEntry("https://one.example", score(0, RiskLevel.LOW)),
                new AnalysisEntry("https://two.example", score(45, RiskLevel.MEDIUM, "longUrl")),
                new AnalysisEntry("https://three.example", score(90, RiskLevel.HIGH, "homograph"))));

        assertTrue(Files.exists(file));
        String html = readFile(file);
        assertEquals(3, countOccurrences(html, "<tr class="));
        assertTrue(html.contains("https://one.example"));
        assertTrue(html.contains("https://two.example"));
        assertTrue(html.contains("https://three.example"));
    }

    @Test
    void sortsHighRiskFirstThenMediumThenLow(@TempDir Path dir) {
        Path file = dir.resolve("report.html");
        HtmlReportWriter writer = new HtmlReportWriter(file, true, "1.0.0", err);

        writer.write(List.of(
                new AnalysisEntry("https://low.example", score(0, RiskLevel.LOW)),
                new AnalysisEntry("https://high.example", score(90, RiskLevel.HIGH, "homograph")),
                new AnalysisEntry("https://medium.example", score(45, RiskLevel.MEDIUM, "longUrl"))));

        String html = readFile(file);
        int highIndex = html.indexOf("https://high.example");
        int mediumIndex = html.indexOf("https://medium.example");
        int lowIndex = html.indexOf("https://low.example");

        assertTrue(highIndex >= 0 && mediumIndex >= 0 && lowIndex >= 0);
        assertTrue(highIndex < mediumIndex, "HIGH row should appear before MEDIUM row");
        assertTrue(mediumIndex < lowIndex, "MEDIUM row should appear before LOW row");
    }

    @Test
    void escapesSpecialCharactersInTarget(@TempDir Path dir) {
        Path file = dir.resolve("report.html");
        HtmlReportWriter writer = new HtmlReportWriter(file, true, "1.0.0", err);

        String trickyUrl = "https://evil.example/?a=<script>alert(1)</script>&b=\"x\"";
        writer.write(List.of(new AnalysisEntry(trickyUrl, score(90, RiskLevel.HIGH, "homograph"))));

        String html = readFile(file);
        assertFalse(html.contains("<script>alert(1)</script>"), "raw script tag must not appear unescaped");
        assertTrue(html.contains("&lt;script&gt;"));
        assertTrue(html.contains("&amp;b="));
        assertTrue(html.contains("&quot;x&quot;"));
    }

    @Test
    void summaryCountsMatchInputData(@TempDir Path dir) {
        Path file = dir.resolve("report.html");
        HtmlReportWriter writer = new HtmlReportWriter(file, true, "1.0.0", err);

        writer.write(List.of(
                new AnalysisEntry("https://a.example", score(0, RiskLevel.LOW)),
                new AnalysisEntry("https://b.example", score(0, RiskLevel.LOW)),
                new AnalysisEntry("https://c.example", score(45, RiskLevel.MEDIUM, "longUrl")),
                new AnalysisEntry("https://d.example", score(90, RiskLevel.HIGH, "homograph")),
                new AnalysisEntry("https://e.example", score(90, RiskLevel.HIGH, "homograph"))));

        String html = readFile(file);
        // 2 LOW, 1 MEDIUM, 2 HIGH out of 5 total.
        assertTrue(html.contains("5 items scanned"));
        assertTrue(html.contains(">2</span> <span class=\"stat-label\">LOW</span> <span class=\"stat-pct\">(40.0%)"));
        assertTrue(html.contains(">1</span> <span class=\"stat-label\">MEDIUM</span> "
                + "<span class=\"stat-pct\">(20.0%)"));
        assertTrue(html.contains(">2</span> <span class=\"stat-label\">HIGH</span> <span class=\"stat-pct\">(40.0%)"));
    }

    @Test
    void disabledWriterNeverCreatesFile(@TempDir Path dir) {
        Path file = dir.resolve("report.html");
        HtmlReportWriter writer = new HtmlReportWriter(file, false, "1.0.0", err);

        writer.write(List.of(new AnalysisEntry("https://example.com", score(0, RiskLevel.LOW))));

        assertFalse(Files.exists(file));
    }

    @Test
    void createsMissingParentDirectories(@TempDir Path dir) {
        Path file = dir.resolve("nested/reports/report.html");
        HtmlReportWriter writer = new HtmlReportWriter(file, true, "1.0.0", err);

        writer.write(List.of(new AnalysisEntry("https://example.com", score(0, RiskLevel.LOW))));

        assertTrue(Files.exists(file));
    }

    @Test
    void ioErrorPrintsWarningAndDoesNotThrow(@TempDir Path dir) throws Exception {
        Path unwritable = dir.resolve("report-as-dir");
        Files.createDirectory(unwritable);

        HtmlReportWriter writer = new HtmlReportWriter(unwritable, true, "1.0.0", err);
        writer.write(List.of(new AnalysisEntry("https://example.com", score(0, RiskLevel.LOW))));

        assertTrue(Files.isDirectory(unwritable));
        String warnings = errBytes.toString(StandardCharsets.UTF_8);
        assertTrue(warnings.contains("could not write HTML report"), "stderr was: " + warnings);
    }

    @Test
    void selfContainedDocumentHasNoExternalReferences(@TempDir Path dir) {
        Path file = dir.resolve("report.html");
        HtmlReportWriter writer = new HtmlReportWriter(file, true, "1.0.0", err);

        writer.write(List.of(new AnalysisEntry("https://example.com", score(0, RiskLevel.LOW))));

        String html = readFile(file);
        assertFalse(html.contains("<script"), "report must not require JavaScript");
        assertFalse(html.contains("http://") && html.contains("cdn"), "report must not load external assets");
        assertTrue(html.contains("<style>"), "CSS must be inlined");
    }

    @Test
    void renderIncludesTypeColumnForEmailEntries() {
        HtmlReportWriter writer = new HtmlReportWriter(Path.of("unused.html"), true, "1.0.0", err);

        String html = writer.render(List.of(
                new AnalysisEntry("phish.eml", score(80, RiskLevel.HIGH, "senderMismatch"),
                        HistoryWriter.TargetType.EMAIL)), Instant.parse("2026-01-01T00:00:00Z"));

        assertTrue(html.contains("phish.eml"));
        assertTrue(html.contains("EMAIL"));
    }

    private static String readFile(Path file) {
        try {
            return Files.readString(file, StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
