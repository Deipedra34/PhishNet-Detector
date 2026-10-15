package com.phishnet.cli;

import com.phishnet.analyzer.UrlAnalyzer;
import com.phishnet.analyzer.WhoisClient;
import com.phishnet.history.HistoryDatabase;
import com.phishnet.model.DomainAgeResult;
import com.phishnet.model.PhishNetConfig;
import com.phishnet.model.RiskLevel;
import com.phishnet.model.RiskScore;
import com.phishnet.model.Signal;
import com.phishnet.model.SignalCategory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@code phishnet history list|search|stats}, driven through {@link Main#run} like the
 * real CLI. Each test reads a database seeded under a JUnit temp directory.
 */
class HistoryCommandTest {

    private record Captured(int exitCode, String stdout, String stderr) {
    }

    private static final WhoisClient OFFLINE_WHOIS = (server, query, timeoutMillis) -> {
        throw new IOException("network disabled in tests");
    };
    private static final UrlAnalyzer URLS = new UrlAnalyzer(PhishNetConfig.defaultConfig());

    @TempDir
    Path tempDir;

    private Path database;

    @BeforeEach
    void setUp() {
        database = tempDir.resolve("history.db");
    }

    private static Captured runMain(String... args) {
        ByteArrayOutputStream outBytes = new ByteArrayOutputStream();
        ByteArrayOutputStream errBytes = new ByteArrayOutputStream();
        try (PrintStream out = new PrintStream(outBytes, true, StandardCharsets.UTF_8);
             PrintStream err = new PrintStream(errBytes, true, StandardCharsets.UTF_8)) {
            int code = Main.run(args, out, err, OFFLINE_WHOIS);
            return new Captured(code, outBytes.toString(StandardCharsets.UTF_8),
                    errBytes.toString(StandardCharsets.UTF_8));
        }
    }

    /** Runs a history subcommand against the test database, with colors off. */
    private Captured history(String subcommand, String... options) {
        String[] args = new String[options.length + 5];
        args[0] = "history";
        args[1] = subcommand;
        args[2] = "--history-db";
        args[3] = database.toString();
        args[4] = "--no-color";
        System.arraycopy(options, 0, args, 5, options.length);
        return runMain(args);
    }

    private static RiskScore score(int value, RiskLevel level, String... signalIds) {
        List<Signal> signals = java.util.Arrays.stream(signalIds)
                .map(id -> new Signal(id, SignalCategory.URL, "why " + id + " fired"))
                .toList();
        return new RiskScore(value, level, signals, "recommendation");
    }

    private void seedUrl(String timestamp, String url, int value, RiskLevel level, String... signalIds) {
        HistoryDatabase db = new HistoryDatabase(database, true, System.err,
                Clock.fixed(Instant.parse(timestamp), ZoneOffset.UTC));
        db.recordUrl(url, URLS.analyze(url).components(), score(value, level, signalIds), DomainAgeResult.skipped());
    }

    private void seedEmail(String timestamp, String label, String sender, String subject, int value, RiskLevel level) {
        HistoryDatabase db = new HistoryDatabase(database, true, System.err,
                Clock.fixed(Instant.parse(timestamp), ZoneOffset.UTC));
        db.recordEmail(label, sender, subject, score(value, level, "senderMismatch"));
    }

    /** Three URL scans and one email scan, on separate days (noon UTC, so every time zone keeps the date). */
    private void seedSample() {
        seedUrl("2026-10-01T12:00:00Z", "https://example.com", 0, RiskLevel.LOW);
        seedUrl("2026-10-03T12:00:00Z", "http://paypa1-login.tk/verify", 85, RiskLevel.HIGH,
                "typosquatting", "suspiciousTld");
        seedUrl("2026-10-05T12:00:00Z", "http://192.168.1.1/login", 45, RiskLevel.MEDIUM, "ipAddressHost");
        seedEmail("2026-10-07T12:00:00Z", "invoice.eml", "billing@paypa1-login.tk", "Invoice overdue",
                70, RiskLevel.HIGH);
    }

    // --- list -------------------------------------------------------------------

    @Test
    void listShowsTableNewestFirst() {
        seedSample();

        Captured result = history("list");

        assertEquals(0, result.exitCode(), result.stderr());
        List<String> lines = result.stdout().lines().toList();
        assertTrue(lines.get(0).matches("ID\\s+TIME\\s+TYPE\\s+SCORE\\s+RISK\\s+TARGET"), lines.get(0));
        assertTrue(lines.get(1).matches("\\s*4\\s+2026-10-0\\d \\d\\d:\\d\\d\\s+EMAIL\\s+70\\s+HIGH\\s+invoice\\.eml"),
                lines.get(1));
        assertTrue(lines.get(2).endsWith("http://192.168.1.1/login"), lines.get(2));
        assertTrue(lines.get(3).endsWith("http://paypa1-login.tk/verify"), lines.get(3));
        assertTrue(lines.get(4).endsWith("https://example.com"), lines.get(4));
        assertTrue(result.stdout().contains("4 scan(s) shown (database: " + database + ")"), result.stdout());
        assertFalse(result.stdout().contains("\u001B["), "no ANSI codes with --no-color");
    }

    @Test
    void listRespectsLimit() {
        seedSample();

        Captured result = history("list", "--limit", "2");

        assertEquals(0, result.exitCode(), result.stderr());
        assertTrue(result.stdout().contains("invoice.eml"));
        assertTrue(result.stdout().contains("192.168.1.1"));
        assertFalse(result.stdout().contains("example.com"));
        assertTrue(result.stdout().contains("2 scan(s) shown"));
    }

    @Test
    void listQuietPrintsOneMachineParsableLinePerScan() {
        seedSample();

        Captured result = history("list", "--quiet");

        assertEquals(0, result.exitCode(), result.stderr());
        assertEquals(List.of(
                        "HIGH 70 invoice.eml",
                        "MEDIUM 45 http://192.168.1.1/login",
                        "HIGH 85 http://paypa1-login.tk/verify",
                        "LOW 0 https://example.com"),
                result.stdout().lines().toList());
    }

    @Test
    void listVerboseShowsDomainSubjectAndSignals() {
        seedSample();

        Captured result = history("list", "--verbose");

        assertEquals(0, result.exitCode(), result.stderr());
        assertTrue(result.stdout().contains("Domain: paypa1-login.tk"), result.stdout());
        assertTrue(result.stdout().contains("Subject: Invoice overdue"), result.stdout());
        assertTrue(result.stdout().contains("- [typosquatting] why typosquatting fired"), result.stdout());
        assertTrue(result.stdout().contains("Signals: none"), result.stdout());
    }

    @Test
    void listOnMissingDatabaseSaysSoWithoutCreatingIt() {
        Captured result = history("list");

        assertEquals(0, result.exitCode(), result.stderr());
        assertTrue(result.stdout().contains("No scans recorded yet"), result.stdout());
        assertFalse(Files.exists(database));
    }

    @Test
    void listQuietOnEmptyDatabasePrintsNothing() {
        Captured result = history("list", "-q");

        assertEquals(0, result.exitCode());
        assertEquals("", result.stdout());
    }

    @Test
    void verboseAndQuietAreMutuallyExclusive() {
        Captured result = history("list", "--verbose", "--quiet");

        assertEquals(2, result.exitCode());
        assertTrue(result.stderr().contains("mutually exclusive"), result.stderr());
    }

    @Test
    void negativeLimitIsUsageError() {
        Captured result = history("list", "--limit", "-1");

        assertEquals(2, result.exitCode());
        assertTrue(result.stderr().contains("--limit"), result.stderr());
    }

    // --- search -----------------------------------------------------------------

    @Test
    void searchByTargetSubstring() {
        seedSample();

        Captured result = history("search", "--target", "PAYPA1", "-q");

        assertEquals(0, result.exitCode(), result.stderr());
        // The email matches through its sender domain.
        assertEquals(List.of("HIGH 70 invoice.eml", "HIGH 85 http://paypa1-login.tk/verify"),
                result.stdout().lines().toList());
    }

    @Test
    void searchByRiskLevelIsCaseInsensitive() {
        seedSample();

        Captured result = history("search", "--risk", "medium", "-q");

        assertEquals(0, result.exitCode(), result.stderr());
        assertEquals(List.of("MEDIUM 45 http://192.168.1.1/login"), result.stdout().lines().toList());
    }

    @Test
    void searchCombinesRiskTypeAndDateRange() {
        seedSample();

        Captured result = history("search", "--risk", "HIGH", "--type", "URL",
                "--since", "2026-10-02", "--until", "2026-10-07", "-q");

        assertEquals(0, result.exitCode(), result.stderr());
        assertEquals(List.of("HIGH 85 http://paypa1-login.tk/verify"), result.stdout().lines().toList());
    }

    @Test
    void searchUntilIncludesTheWholeDay() {
        seedSample();

        Captured result = history("search", "--since", "2026-10-05", "--until", "2026-10-05", "-q");

        assertEquals(List.of("MEDIUM 45 http://192.168.1.1/login"), result.stdout().lines().toList());
    }

    @Test
    void searchWithNoMatchesSaysSo() {
        seedSample();

        Captured result = history("search", "--target", "not-there");

        assertEquals(0, result.exitCode());
        assertTrue(result.stdout().contains("No matching scans"), result.stdout());
    }

    @Test
    void invalidDateIsUsageError() {
        Captured result = history("search", "--since", "10/01/2026");

        assertEquals(2, result.exitCode());
        assertTrue(result.stderr().contains("not a date in YYYY-MM-DD format"), result.stderr());
    }

    @Test
    void sinceAfterUntilIsUsageError() {
        Captured result = history("search", "--since", "2026-10-09", "--until", "2026-10-01");

        assertEquals(2, result.exitCode());
        assertTrue(result.stderr().contains("must not be after"), result.stderr());
    }

    @Test
    void invalidRiskLevelIsUsageError() {
        Captured result = history("search", "--risk", "CRITICAL");

        assertEquals(2, result.exitCode());
        assertTrue(result.stderr().contains("--risk"), result.stderr());
    }

    // --- stats ------------------------------------------------------------------

    @Test
    void statsShowsTotalsAndFlaggedDomains() {
        seedSample();

        Captured result = history("stats");

        assertEquals(0, result.exitCode(), result.stderr());
        String out = result.stdout();
        assertTrue(out.contains("Total scans: 4"), out);
        assertTrue(out.matches("(?s).*HIGH\\s+2\\s+50\\.0%.*"), out);
        assertTrue(out.matches("(?s).*MEDIUM\\s+1\\s+25\\.0%.*"), out);
        assertTrue(out.matches("(?s).*LOW\\s+1\\s+25\\.0%.*"), out);
        assertTrue(out.matches("(?s).*URL\\s+3.*EMAIL\\s+1.*"), out);
        // paypa1-login.tk: one HIGH URL scan + one HIGH email (sender domain).
        assertTrue(out.matches("(?s).*1\\. paypa1-login\\.tk\\s+2.*2\\. 192\\.168\\.1\\.1\\s+1.*"), out);
        assertFalse(out.contains("example.com"), "LOW scans are never flagged");
    }

    @Test
    void statsQuietPrintsOneLine() {
        seedSample();

        Captured result = history("stats", "--quiet");

        assertEquals(0, result.exitCode(), result.stderr());
        assertEquals("total=4 high=2 medium=1 low=1 url=3 email=1", result.stdout().trim());
    }

    @Test
    void statsOnEmptyDatabase() {
        Captured result = history("stats");

        assertEquals(0, result.exitCode());
        assertTrue(result.stdout().contains("No scans recorded yet"), result.stdout());
    }

    // --- general ----------------------------------------------------------------

    @Test
    void historyWithoutSubcommandIsUsageError() {
        Captured result = runMain("history");

        assertEquals(2, result.exitCode());
        assertTrue(result.stderr().contains("Missing required command"), result.stderr());
        assertTrue(result.stderr().contains("list"), result.stderr());
    }

    @Test
    void unknownSubcommandIsUsageError() {
        Captured result = runMain("history", "delete");

        assertEquals(2, result.exitCode());
    }

    @Test
    void historyHelpListsSubcommands() {
        Captured result = runMain("history", "--help");

        assertEquals(0, result.exitCode());
        assertTrue(result.stdout().contains("phishnet history"), result.stdout());
        assertTrue(result.stdout().contains("list"));
        assertTrue(result.stdout().contains("search"));
        assertTrue(result.stdout().contains("stats"));
    }

    @Test
    void subcommandHelpDescribesOptions() {
        Captured result = runMain("history", "search", "--help");

        assertEquals(0, result.exitCode());
        assertTrue(result.stdout().contains("phishnet history search"), result.stdout());
        assertTrue(result.stdout().contains("--target"));
        assertTrue(result.stdout().contains("--risk"));
        assertTrue(result.stdout().contains("LOW, MEDIUM, HIGH"), result.stdout());
    }

    @Test
    void unreadableDatabaseIsReportedAsError() throws IOException {
        Files.writeString(database, "this is not an SQLite database, just some text that is long enough "
                + "to fill the header page check that SQLite performs when opening a file", StandardCharsets.UTF_8);

        Captured result = history("list");

        assertEquals(1, result.exitCode());
        assertTrue(result.stderr().contains("could not read scan history database"), result.stderr());
    }

    @Test
    void scanThenHistoryRoundTripThroughTheCli() {
        Captured scan = runMain("--url", "http://192.168.1.1/login", "--no-whois", "--no-history",
                "--history-db", database.toString(), "--json");
        assertEquals(0, scan.exitCode(), scan.stderr());

        Captured result = history("list", "-q");

        assertEquals(1, result.stdout().lines().count(), result.stdout());
        assertTrue(result.stdout().endsWith("http://192.168.1.1/login" + System.lineSeparator()), result.stdout());
    }
}
