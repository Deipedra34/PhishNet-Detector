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
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class HistoryWriterTest {

    private static final String HEADER = "timestamp,target,type,risk_score,risk_label,signals";

    private final ByteArrayOutputStream errBytes = new ByteArrayOutputStream();
    private final PrintStream err = new PrintStream(errBytes, true, StandardCharsets.UTF_8);

    private static RiskScore score(int value, RiskLevel level, String... signalIds) {
        List<Signal> signals = java.util.Arrays.stream(signalIds)
                .map(id -> new Signal(id, SignalCategory.URL, id + " description"))
                .toList();
        return new RiskScore(value, level, signals, "recommendation text");
    }

    private static List<String> readLines(Path file) throws Exception {
        return Files.readAllLines(file, StandardCharsets.UTF_8);
    }

    @Test
    void writesHeaderThenRowOnFirstRun(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("phishnet-history.csv");
        HistoryWriter writer = new HistoryWriter(file, true, err);

        writer.record("https://example.com", HistoryWriter.TargetType.URL, score(0, RiskLevel.LOW));

        List<String> lines = readLines(file);
        assertEquals(2, lines.size());
        assertEquals(HEADER, lines.get(0));
        assertTrue(lines.get(1).endsWith(",https://example.com,URL,0,LOW,"));
    }

    @Test
    void appendsRowsWithoutRepeatingHeaderOnSubsequentRuns(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("phishnet-history.csv");

        new HistoryWriter(file, true, err)
                .record("https://a.example", HistoryWriter.TargetType.URL, score(10, RiskLevel.LOW, "urlShortener"));
        new HistoryWriter(file, true, err)
                .record("b.eml", HistoryWriter.TargetType.EMAIL, score(80, RiskLevel.HIGH, "senderMismatch"));

        List<String> lines = readLines(file);
        assertEquals(3, lines.size());
        assertEquals(HEADER, lines.get(0));
        assertEquals(1, lines.stream().filter(l -> l.equals(HEADER)).count());
        assertTrue(lines.get(1).endsWith(",https://a.example,URL,10,LOW,urlShortener"));
        assertTrue(lines.get(2).endsWith(",b.eml,EMAIL,80,HIGH,senderMismatch"));
    }

    @Test
    void joinsMultipleSignalsWithSemicolons(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("history.csv");
        new HistoryWriter(file, true, err).record("http://evil.tk", HistoryWriter.TargetType.URL,
                score(70, RiskLevel.HIGH, "suspiciousTld", "typosquatting", "nestedRedirect"));

        List<String> lines = readLines(file);
        assertTrue(lines.get(1).endsWith(",http://evil.tk,URL,70,HIGH,suspiciousTld;typosquatting;nestedRedirect"));
    }

    @Test
    void escapesFieldsContainingCommasAndQuotes(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("history.csv");
        String trickyTarget = "http://evil.example/?a=1,2&b=\"quoted\"";
        new HistoryWriter(file, true, err)
                .record(trickyTarget, HistoryWriter.TargetType.URL, score(30, RiskLevel.MEDIUM));

        List<String> lines = readLines(file);
        // Comma + quote => whole field quoted, internal quotes doubled.
        assertTrue(lines.get(1).contains("\"http://evil.example/?a=1,2&b=\"\"quoted\"\"\""),
                "row was: " + lines.get(1));
        // Still exactly one data row (the embedded comma did not split the record).
        assertEquals(2, lines.size());
    }

    @Test
    void csvFieldEscapingRules() {
        assertEquals("plain", HistoryWriter.csvField("plain"));
        assertEquals("\"a,b\"", HistoryWriter.csvField("a,b"));
        assertEquals("\"a\"\"b\"", HistoryWriter.csvField("a\"b"));
        assertEquals("\"line1\nline2\"", HistoryWriter.csvField("line1\nline2"));
        assertEquals("", HistoryWriter.csvField(null));
    }

    @Test
    void noHistoryFlagSuppressesAllWriting(@TempDir Path dir) {
        Path file = dir.resolve("phishnet-history.csv");
        HistoryWriter writer = new HistoryWriter(file, false, err);

        writer.record("https://example.com", HistoryWriter.TargetType.URL, score(0, RiskLevel.LOW));

        assertFalse(Files.exists(file));
    }

    @Test
    void batchModeWritesOneRowPerItem(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("phishnet-history.csv");
        HistoryWriter writer = new HistoryWriter(file, true, err);

        writer.record("https://one.example", HistoryWriter.TargetType.URL, score(0, RiskLevel.LOW));
        writer.record("https://two.example", HistoryWriter.TargetType.URL, score(45, RiskLevel.MEDIUM, "longUrl"));
        writer.record("https://three.example", HistoryWriter.TargetType.URL, score(90, RiskLevel.HIGH, "homograph"));

        List<String> lines = readLines(file);
        assertEquals(4, lines.size()); // header + 3 rows
        assertTrue(lines.get(1).contains(",https://one.example,URL,0,LOW,"));
        assertTrue(lines.get(2).contains(",https://two.example,URL,45,MEDIUM,longUrl"));
        assertTrue(lines.get(3).contains(",https://three.example,URL,90,HIGH,homograph"));
    }

    @Test
    void firstColumnIsAnIso8601Timestamp(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("history.csv");
        new HistoryWriter(file, true, err)
                .record("https://example.com", HistoryWriter.TargetType.URL, score(0, RiskLevel.LOW));

        String firstColumn = readLines(file).get(1).split(",")[0];
        // Parses as an ISO-8601 instant without throwing.
        java.time.Instant.parse(firstColumn);
    }

    @Test
    void ioErrorPrintsWarningAndDoesNotThrow(@TempDir Path dir) throws Exception {
        // Point the history "file" at an existing directory, so opening it for
        // writing fails on any platform.
        Path unwritable = dir.resolve("history-as-dir");
        Files.createDirectory(unwritable);

        HistoryWriter writer = new HistoryWriter(unwritable, true, err);
        writer.record("https://example.com", HistoryWriter.TargetType.URL, score(0, RiskLevel.LOW));
        writer.record("https://example.com/2", HistoryWriter.TargetType.URL, score(0, RiskLevel.LOW));

        assertTrue(Files.isDirectory(unwritable));
        String warnings = errBytes.toString(StandardCharsets.UTF_8);
        assertTrue(warnings.contains("could not write scan history"), "stderr was: " + warnings);
        // Warns at most once even across multiple failed records.
        assertEquals(1, warnings.lines().filter(l -> l.contains("could not write scan history")).count());
    }
}
