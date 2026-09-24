package com.phishnet.cli;

import com.phishnet.analyzer.WhoisClient;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDate;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MainTest {

    private record Captured(int exitCode, String stdout, String stderr) {
    }

    /** Stands in for the real socket client so no test in this class can ever reach a WHOIS server. */
    private static final WhoisClient OFFLINE_WHOIS = (server, query, timeoutMillis) -> {
        throw new IOException("network disabled in tests");
    };

    private static Captured runMain(String... args) {
        // WHOIS lookups are network calls: unless a test is exercising them (via
        // runMainWithWhois), turn them off exactly as a CI user would.
        String[] effectiveArgs = Arrays.copyOf(args, args.length + 1);
        effectiveArgs[args.length] = "--no-whois";
        return runMainWithWhois(OFFLINE_WHOIS, effectiveArgs);
    }

    private static Captured runMainWithWhois(WhoisClient whoisClient, String... args) {
        // Scan-history logging is a side effect of every scan and defaults to
        // ./phishnet-history.csv in the working directory. Unless a test is
        // explicitly exercising history, suppress it so the suite never writes
        // into the real module directory. Tests that pass their own
        // --history-file / --no-history are left untouched.
        String[] effectiveArgs = args;
        boolean touchesHistory = Arrays.stream(args)
                .anyMatch(a -> a.equals("--history-file") || a.equals("--no-history"));
        if (!touchesHistory) {
            effectiveArgs = Arrays.copyOf(args, args.length + 1);
            effectiveArgs[args.length] = "--no-history";
        }

        ByteArrayOutputStream outBytes = new ByteArrayOutputStream();
        ByteArrayOutputStream errBytes = new ByteArrayOutputStream();
        try (PrintStream out = new PrintStream(outBytes, true, StandardCharsets.UTF_8);
             PrintStream err = new PrintStream(errBytes, true, StandardCharsets.UTF_8)) {
            int code = Main.run(effectiveArgs, out, err, whoisClient);
            out.flush();
            err.flush();
            return new Captured(code, outBytes.toString(StandardCharsets.UTF_8),
                    errBytes.toString(StandardCharsets.UTF_8));
        }
    }

    @Test
    void urlModeHumanReadableOutput() {
        Captured result = runMain("--url", "http://192.168.1.1/login");
        assertEquals(0, result.exitCode());
        assertTrue(result.stdout().contains("ipAddressHost"));
        assertTrue(result.stdout().contains("Risk Score"));
    }

    @Test
    void urlModeJsonOutput() {
        Captured result = runMain("--url", "https://bit.ly/xyz", "--json");
        assertEquals(0, result.exitCode());
        assertTrue(result.stdout().trim().startsWith("{"));
        assertTrue(result.stdout().contains("urlShortener"));
    }

    @Test
    void emailModeReadsFileAndScoresIt(@TempDir Path tempDir) throws Exception {
        Path emlFile = tempDir.resolve("phish.eml");
        Files.writeString(emlFile,
                "From: \"PayPal\" <alert@random-mailer.info>\n"
                        + "To: victim@example.com\n"
                        + "Subject: Verify immediately\n"
                        + "Content-Type: text/plain; charset=UTF-8\n\n"
                        + "Your account will be suspended. Verify immediately: http://192.168.1.1/login\n",
                StandardCharsets.UTF_8);

        Captured result = runMain("--email", emlFile.toString());

        assertEquals(0, result.exitCode());
        assertTrue(result.stdout().contains("senderMismatch"));
        assertTrue(result.stdout().contains("urgencyLanguage"));
        assertTrue(result.stdout().contains("riskyEmbeddedLink"));
    }

    @Test
    void batchModeProcessesEachLineAndPrintsSummary(@TempDir Path tempDir) throws Exception {
        Path batchFile = tempDir.resolve("urls.txt");
        Files.writeString(batchFile,
                "# comment line, should be skipped\n"
                        + "https://example.com\n"
                        + "\n"
                        + "http://192.168.1.1/login\n"
                        + "http://free-prize.tk\n",
                StandardCharsets.UTF_8);

        Captured result = runMain("--batch", batchFile.toString());

        assertEquals(0, result.exitCode());
        assertTrue(result.stdout().contains("example.com"));
        assertTrue(result.stdout().contains("192.168.1.1"));
        assertTrue(result.stdout().contains("free-prize.tk"));
        assertTrue(result.stdout().contains("Summary: 3 URL(s) analyzed"));
    }

    @Test
    void batchModeJsonOutputsArray(@TempDir Path tempDir) throws Exception {
        Path batchFile = tempDir.resolve("urls.txt");
        Files.writeString(batchFile, "https://example.com\nhttp://192.168.1.1/login\n", StandardCharsets.UTF_8);

        Captured result = runMain("--batch", batchFile.toString(), "--json");

        assertEquals(0, result.exitCode());
        assertTrue(result.stdout().trim().startsWith("["));
    }

    // --- batch progress bar: suppressed / redirected under quiet, json, non-TTY -
    //
    // These run through Main.run() with injected ByteArrayOutputStream-backed
    // streams, but the progress bar's TTY check (ColorSupport.isTty(), shared
    // with color detection) reads the real process console, not those injected
    // streams - so whether the bar actually renders here depends on how the test
    // JVM itself was launched, not on anything these tests control. Rather than
    // assert "never renders" (flaky - see ProgressReporterTest for that, driven
    // explicitly by an injected isTty flag), these assert the invariant that
    // must hold either way: quiet output has exactly its two machine-parsable
    // lines and never the bar's own text, JSON stdout stays valid JSON with the
    // bar never leaking into it, and default-mode output stays well-formed even
    // if a bar rendered ahead of it.
    private static final java.util.regex.Pattern PROGRESS_BAR_PATTERN =
            java.util.regex.Pattern.compile("\\[[#-]{20}] \\d+% \\(\\d+/\\d+\\)");

    @Test
    void batchModeQuietOutputNeverContainsProgressBarText(@TempDir Path tempDir) throws Exception {
        Path batchFile = tempDir.resolve("urls.txt");
        Files.writeString(batchFile, "https://example.com\nhttp://192.168.1.1/login\n", StandardCharsets.UTF_8);

        Captured result = runMain("--batch", batchFile.toString(), "--quiet");

        assertEquals(0, result.exitCode());
        assertFalse(PROGRESS_BAR_PATTERN.matcher(result.stdout()).find());
        String[] lines = result.stdout().strip().split("\\r?\\n");
        assertEquals(2, lines.length);
    }

    @Test
    void batchModeJsonStdoutStaysValidJsonWithNoProgressBarText(@TempDir Path tempDir) throws Exception {
        Path batchFile = tempDir.resolve("urls.txt");
        Files.writeString(batchFile, "https://example.com\nhttp://192.168.1.1/login\n", StandardCharsets.UTF_8);

        Captured result = runMain("--batch", batchFile.toString(), "--json");

        assertEquals(0, result.exitCode());
        assertFalse(PROGRESS_BAR_PATTERN.matcher(result.stdout()).find(),
                "progress bar text must never reach stdout in --json mode");
        assertTrue(result.stdout().trim().startsWith("["));
        assertTrue(result.stdout().trim().endsWith("]"));
    }

    @Test
    void batchModeDefaultOutputStaysWellFormedAheadOfOrWithoutProgressBar(@TempDir Path tempDir) throws Exception {
        Path batchFile = tempDir.resolve("urls.txt");
        Files.writeString(batchFile, "https://example.com\nhttp://192.168.1.1/login\n", StandardCharsets.UTF_8);

        Captured result = runMain("--batch", batchFile.toString());

        assertEquals(0, result.exitCode());
        assertTrue(result.stdout().contains("Target: https://example.com"));
        assertTrue(result.stdout().contains("Summary: 2 URL(s) analyzed"));
    }

    // --- picocli-generated help/version ---------------------------------------

    @Test
    void helpFlagPrintsUsageAndExitsZero() {
        Captured result = runMain("--help");
        assertEquals(0, result.exitCode());
        assertTrue(result.stdout().contains("Usage:"));
        assertTrue(result.stdout().contains("phishnet"));
    }

    @Test
    void shortHelpFlagAlsoWorks() {
        Captured result = runMain("-h");
        assertEquals(0, result.exitCode());
        assertTrue(result.stdout().contains("Usage:"));
    }

    @Test
    void helpOutputIsGroupedIntoInputAndOutputSections() {
        Captured result = runMain("--help");
        assertTrue(result.stdout().contains("Input options:"));
        assertTrue(result.stdout().contains("Output options:"));
        assertTrue(result.stdout().contains("--url"));
        assertTrue(result.stdout().contains("--email"));
        assertTrue(result.stdout().contains("--batch"));
        assertTrue(result.stdout().contains("--json"));
        assertTrue(result.stdout().contains("--no-color"));
        assertTrue(result.stdout().contains("--verbose"));
        assertTrue(result.stdout().contains("--quiet"));
        assertTrue(result.stdout().contains("--history-file"));
        assertTrue(result.stdout().contains("--no-history"));
        assertTrue(result.stdout().contains("--html-report"));
    }

    @Test
    void helpOutputIncludesUsageExamples() {
        Captured result = runMain("--help");
        assertTrue(result.stdout().contains("phishnet --url https://example.com"));
        assertTrue(result.stdout().contains("phishnet --email suspicious.eml --verbose"));
        assertTrue(result.stdout().contains("phishnet --batch urls.txt --json"));
    }

    @Test
    void versionFlagPrintsProjectVersionAndExitsZero() {
        Captured result = runMain("--version");
        assertEquals(0, result.exitCode());
        assertTrue(result.stdout().contains("phishnet"));
        // Must reflect the actual Maven build version (read from the filtered
        // version.properties resource), not a hand-typed, driftable literal.
        String pomVersion = readPomVersion();
        assertTrue(result.stdout().contains(pomVersion),
                "expected version output to contain '" + pomVersion + "' but was: " + result.stdout());
    }

    @Test
    void shortVersionFlagAlsoWorks() {
        Captured result = runMain("-V");
        assertEquals(0, result.exitCode());
        assertTrue(result.stdout().contains("phishnet"));
    }

    private static String readPomVersion() {
        try (java.io.InputStream in = MainTest.class.getResourceAsStream("/version.properties")) {
            java.util.Properties props = new java.util.Properties();
            props.load(in);
            return props.getProperty("version");
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    // --- usage errors -----------------------------------------------------------

    @Test
    void noModeFlagPrintsErrorAndUsage() {
        Captured result = runMain("--json");
        assertEquals(2, result.exitCode());
        assertTrue(result.stderr().contains("Error"));
        assertTrue(result.stderr().contains("Usage:"));
    }

    @Test
    void multipleModeFlagsAreRejected() {
        Captured result = runMain("--url", "https://example.com", "--email", "x.eml");
        assertEquals(2, result.exitCode());
        assertTrue(result.stderr().contains("Error"));
    }

    @Test
    void unknownFlagIsRejected() {
        Captured result = runMain("--nope");
        assertEquals(2, result.exitCode());
        assertTrue(result.stderr().contains("Unknown option"));
    }

    @Test
    void missingEmailFileReportsErrorInsteadOfCrashing() {
        Captured result = runMain("--email", "does-not-exist-anywhere.eml");
        assertEquals(1, result.exitCode());
        assertTrue(result.stderr().contains("Error"));
    }

    @Test
    void missingBatchFileReportsErrorInsteadOfCrashing() {
        Captured result = runMain("--batch", "does-not-exist-anywhere.txt");
        assertEquals(1, result.exitCode());
        assertTrue(result.stderr().contains("Error"));
    }

    @Test
    void customConfigOverridesDefaultBrandList(@TempDir Path tempDir) throws Exception {
        Path configFile = tempDir.resolve("custom-config.yaml");
        Files.writeString(configFile,
                "brands:\n  - acme\n"
                        + "suspiciousTlds: []\n"
                        + "urlShorteners: []\n"
                        + "urgencyKeywords: {}\n"
                        + "scoring:\n"
                        + "  weights:\n    typosquatting: 30\n"
                        + "  mediumThreshold: 30\n  highThreshold: 60\n"
                        + "  typosquattingMaxDistance: 2\n  longUrlThreshold: 75\n"
                        + "  maxQueryParams: 8\n  encodedCharThreshold: 5\n",
                StandardCharsets.UTF_8);

        Captured result = runMain("--url", "http://acm3.com", "--config", configFile.toString());

        assertEquals(0, result.exitCode());
        assertTrue(result.stdout().contains("typosquatting"));
    }

    // --- verbose / quiet / no-color -------------------------------------------

    @Test
    void verboseFlagShowsDetailsSection() {
        Captured result = runMain("--url", "http://paypa1-secure-login.tk/verify", "--verbose");
        assertEquals(0, result.exitCode());
        assertTrue(result.stdout().contains("Details:"));
        assertTrue(result.stdout().contains("host=paypa1-secure-login.tk"));
    }

    @Test
    void defaultModeDoesNotShowDetailsSection() {
        Captured result = runMain("--url", "http://paypa1-secure-login.tk/verify");
        assertEquals(0, result.exitCode());
        assertTrue(!result.stdout().contains("Details:"));
    }

    @Test
    void quietModePrintsSingleLineFormat() {
        Captured result = runMain("--url", "https://example.com", "--quiet");
        assertEquals(0, result.exitCode());
        assertEquals("LOW 0 https://example.com", result.stdout().strip());
    }

    @Test
    void shortQuietFlagAlsoWorks() {
        Captured result = runMain("--url", "https://example.com", "-q");
        assertEquals("LOW 0 https://example.com", result.stdout().strip());
    }

    @Test
    void quietModeExitsOneForHighRisk() {
        Captured result = runMain("--url",
                "http://paypa1-secure-login.tk/verify?redirect=http://evil.tk/x", "--quiet");
        assertEquals(1, result.exitCode());
        assertTrue(result.stdout().startsWith("HIGH"));
    }

    @Test
    void nonQuietModeExitsZeroEvenForHighRisk() {
        Captured result = runMain("--url",
                "http://paypa1-secure-login.tk/verify?redirect=http://evil.tk/x");
        assertEquals(0, result.exitCode());
    }

    @Test
    void verboseAndQuietTogetherIsUsageError() {
        Captured result = runMain("--url", "https://example.com", "--verbose", "--quiet");
        assertEquals(2, result.exitCode());
        assertTrue(result.stderr().contains("--verbose"));
        assertTrue(result.stderr().contains("--quiet"));
        assertTrue(result.stderr().contains("mutually exclusive"));
    }

    @Test
    void shortVerboseAndQuietTogetherIsUsageError() {
        Captured result = runMain("--url", "https://example.com", "-v", "-q");
        assertEquals(2, result.exitCode());
        assertTrue(result.stderr().contains("mutually exclusive"));
    }

    @Test
    void quietModeNeverContainsAnsiEscapeCode() {
        Captured result = runMain("--url",
                "http://paypa1-secure-login.tk/verify?redirect=http://evil.tk/x", "--quiet");
        assertEquals(-1, result.stdout().indexOf(''));
    }

    @Test
    void noColorFlagDoesNotBreakNormalOutput() {
        Captured result = runMain("--url", "http://paypa1-secure-login.tk/verify", "--no-color");
        assertEquals(0, result.exitCode());
        assertEquals(-1, result.stdout().indexOf(''));
        assertTrue(result.stdout().contains("HIGH") || result.stdout().contains("MEDIUM"));
    }

    @Test
    void batchQuietModePrintsOneLinePerUrlNoSummary(@TempDir Path tempDir) throws Exception {
        Path batchFile = tempDir.resolve("urls.txt");
        Files.writeString(batchFile, "https://example.com\nhttp://192.168.1.1/login\n", StandardCharsets.UTF_8);

        Captured result = runMain("--batch", batchFile.toString(), "--quiet");

        assertEquals(0, result.exitCode());
        assertTrue(!result.stdout().contains("Summary"));
        String[] lines = result.stdout().strip().split("\\r?\\n");
        assertEquals(2, lines.length);
    }

    // --- scan history logging ------------------------------------------------

    @Test
    void historyFileOptionRecordsOneRowPerScan(@TempDir Path tempDir) throws Exception {
        Path historyFile = tempDir.resolve("phishnet-history.csv");

        Captured first = runMain("--url", "https://example.com", "--history-file", historyFile.toString());
        assertEquals(0, first.exitCode());

        List<String> lines = Files.readAllLines(historyFile, StandardCharsets.UTF_8);
        assertEquals(2, lines.size());
        assertEquals("timestamp,target,type,risk_score,risk_label,signals,domain_age_days", lines.get(0));
        assertTrue(lines.get(1).contains(",https://example.com,URL,"));

        // A second run appends without rewriting the header.
        runMain("--url", "http://192.168.1.1/login", "--history-file", historyFile.toString());
        lines = Files.readAllLines(historyFile, StandardCharsets.UTF_8);
        assertEquals(3, lines.size());
        assertTrue(lines.get(2).contains(",http://192.168.1.1/login,URL,"));
        assertTrue(lines.get(2).contains("ipAddressHost"));
    }

    @Test
    void historyIsLoggedEvenInJsonMode(@TempDir Path tempDir) throws Exception {
        Path historyFile = tempDir.resolve("history.csv");

        Captured result = runMain("--url", "https://bit.ly/xyz", "--json", "--history-file", historyFile.toString());

        assertEquals(0, result.exitCode());
        assertTrue(result.stdout().trim().startsWith("{"));
        List<String> lines = Files.readAllLines(historyFile, StandardCharsets.UTF_8);
        assertEquals(2, lines.size());
        assertTrue(lines.get(1).contains("urlShortener"));
    }

    @Test
    void noHistoryFlagDisablesLogging(@TempDir Path tempDir) {
        Path historyFile = tempDir.resolve("phishnet-history.csv");

        Captured result = runMain("--url", "https://example.com",
                "--history-file", historyFile.toString(), "--no-history");

        assertEquals(0, result.exitCode());
        assertFalse(Files.exists(historyFile));
    }

    @Test
    void batchModeWritesOneHistoryRowPerItem(@TempDir Path tempDir) throws Exception {
        Path batchFile = tempDir.resolve("urls.txt");
        Files.writeString(batchFile,
                "# comment\nhttps://example.com\n\nhttp://192.168.1.1/login\nhttp://free-prize.tk\n",
                StandardCharsets.UTF_8);
        Path historyFile = tempDir.resolve("phishnet-history.csv");

        Captured result = runMain("--batch", batchFile.toString(), "--history-file", historyFile.toString());

        assertEquals(0, result.exitCode());
        List<String> lines = Files.readAllLines(historyFile, StandardCharsets.UTF_8);
        assertEquals(4, lines.size()); // header + 3 non-comment URLs
        assertTrue(lines.get(1).contains(",https://example.com,URL,"));
        assertTrue(lines.get(2).contains(",http://192.168.1.1/login,URL,"));
        assertTrue(lines.get(3).contains(",http://free-prize.tk,URL,"));
    }

    @Test
    void emailScanIsRecordedWithEmailType(@TempDir Path tempDir) throws Exception {
        Path emlFile = tempDir.resolve("phish.eml");
        Files.writeString(emlFile,
                "From: \"PayPal\" <alert@random-mailer.info>\n"
                        + "To: victim@example.com\n"
                        + "Subject: Verify immediately\n"
                        + "Content-Type: text/plain; charset=UTF-8\n\n"
                        + "Your account will be suspended. Verify immediately: http://192.168.1.1/login\n",
                StandardCharsets.UTF_8);
        Path historyFile = tempDir.resolve("phishnet-history.csv");

        Captured result = runMain("--email", emlFile.toString(), "--history-file", historyFile.toString());

        assertEquals(0, result.exitCode());
        List<String> lines = Files.readAllLines(historyFile, StandardCharsets.UTF_8);
        assertEquals(2, lines.size());
        assertTrue(lines.get(1).contains("," + emlFile + ",EMAIL,"));
    }

    @Test
    void historyWriteFailureWarnsButDoesNotFailScan(@TempDir Path tempDir) {
        // An existing directory can't be opened as a file for writing.
        Path historyDir = tempDir.resolve("history-as-dir");
        assertTrue(historyDir.toFile().mkdir());

        Captured result = runMain("--url", "https://example.com", "--history-file", historyDir.toString());

        assertEquals(0, result.exitCode());
        assertTrue(result.stdout().contains("Risk Score"));
        assertTrue(result.stderr().contains("could not write scan history"));
    }

    // --- HTML report ------------------------------------------------------------

    @Test
    void urlModeWritesHtmlReportWithOneRow(@TempDir Path tempDir) throws Exception {
        Path reportFile = tempDir.resolve("report.html");

        Captured result = runMain("--url", "https://example.com", "--html-report", reportFile.toString());

        assertEquals(0, result.exitCode());
        assertTrue(Files.exists(reportFile));
        String html = Files.readString(reportFile, StandardCharsets.UTF_8);
        assertTrue(html.contains("https://example.com"));
        assertTrue(html.contains("1 item scanned"));
    }

    @Test
    void emailModeWritesHtmlReportWithEmailType(@TempDir Path tempDir) throws Exception {
        Path emlFile = tempDir.resolve("phish.eml");
        Files.writeString(emlFile,
                "From: \"PayPal\" <alert@random-mailer.info>\n"
                        + "To: victim@example.com\n"
                        + "Subject: Verify immediately\n"
                        + "Content-Type: text/plain; charset=UTF-8\n\n"
                        + "Your account will be suspended. Verify immediately: http://192.168.1.1/login\n",
                StandardCharsets.UTF_8);
        Path reportFile = tempDir.resolve("report.html");

        Captured result = runMain("--email", emlFile.toString(), "--html-report", reportFile.toString());

        assertEquals(0, result.exitCode());
        String html = Files.readString(reportFile, StandardCharsets.UTF_8);
        assertTrue(html.contains(emlFile.toString().replace("<", "&lt;").replace(">", "&gt;"))
                || html.contains(emlFile.toString()));
        assertTrue(html.contains("EMAIL"));
    }

    @Test
    void batchModeWritesHtmlReportOnceForWholeBatch(@TempDir Path tempDir) throws Exception {
        Path batchFile = tempDir.resolve("urls.txt");
        Files.writeString(batchFile,
                "https://example.com\nhttp://192.168.1.1/login\nhttp://free-prize.tk\n", StandardCharsets.UTF_8);
        Path reportFile = tempDir.resolve("report.html");

        Captured result = runMain("--batch", batchFile.toString(), "--html-report", reportFile.toString());

        assertEquals(0, result.exitCode());
        String html = Files.readString(reportFile, StandardCharsets.UTF_8);
        assertTrue(html.contains("3 items scanned"));
        assertEquals(3, html.lines().filter(l -> l.contains("<tr class=")).count());
    }

    @Test
    void htmlReportNotWrittenWhenFlagAbsent(@TempDir Path tempDir) {
        Path reportFile = tempDir.resolve("report.html");

        Captured result = runMain("--url", "https://example.com");

        assertEquals(0, result.exitCode());
        assertFalse(Files.exists(reportFile));
    }

    @Test
    void htmlReportCreatesMissingParentDirectory(@TempDir Path tempDir) {
        Path reportFile = tempDir.resolve("nested/reports/report.html");

        Captured result = runMain("--url", "https://example.com", "--html-report", reportFile.toString());

        assertEquals(0, result.exitCode());
        assertTrue(Files.exists(reportFile));
    }

    @Test
    void htmlReportWorksAlongsideJsonAndQuietModes(@TempDir Path tempDir) throws Exception {
        Path reportFile = tempDir.resolve("report.html");

        Captured result = runMain("--url", "https://bit.ly/xyz", "--json", "--html-report", reportFile.toString());

        assertEquals(0, result.exitCode());
        assertTrue(result.stdout().trim().startsWith("{"));
        assertTrue(Files.exists(reportFile));
        assertTrue(Files.readString(reportFile, StandardCharsets.UTF_8).contains("bit.ly"));
    }

    // --- WHOIS domain age ------------------------------------------------------
    // All of these use a fake WhoisClient - nothing here opens a real socket.

    /** A fake registry that reports the domain as created {@code daysAgo} days before today. */
    private static WhoisClient registryReporting(long daysAgo, AtomicInteger calls) {
        String created = LocalDate.now().minusDays(daysAgo).toString();
        return (server, query, timeoutMillis) -> {
            calls.incrementAndGet();
            return "Domain Name: " + query.toUpperCase() + "\r\nCreation Date: " + created + "T10:00:00Z\r\n";
        };
    }

    @Test
    void urlModeShowsDomainAgeAndFlagsNewDomain() {
        AtomicInteger calls = new AtomicInteger();
        Captured result = runMainWithWhois(registryReporting(10, calls), "--url", "https://fresh-site.com/login");

        assertEquals(0, result.exitCode());
        assertTrue(result.stdout().contains("Domain Age: 10 days"), result.stdout());
        assertTrue(result.stdout().contains("[domainAgeNew]"), result.stdout());
        assertEquals(1, calls.get());
    }

    @Test
    void verboseModeShowsCreationDateAndServer() {
        Captured result = runMainWithWhois(registryReporting(400, new AtomicInteger()),
                "--url", "https://example.com", "--verbose");

        String created = LocalDate.now().minusDays(400).toString();
        assertTrue(result.stdout().contains("Domain Age: 13 months (400 days, created " + created
                + ", via whois.verisign-grs.com)"), result.stdout());
    }

    @Test
    void quietModeNeverShowsDomainAge() {
        Captured result = runMainWithWhois(registryReporting(10, new AtomicInteger()),
                "--url", "https://fresh-site.com", "--quiet");

        assertFalse(result.stdout().contains("Domain Age"));
        assertEquals(1, result.stdout().trim().lines().count());
    }

    @Test
    void failedWhoisLookupShowsUnknownAndLeavesScoreNeutral() {
        Captured withFailure = runMainWithWhois(OFFLINE_WHOIS, "--url", "https://bit.ly/xyz");
        Captured withoutWhois = runMain("--url", "https://bit.ly/xyz");

        assertEquals(0, withFailure.exitCode());
        assertTrue(withFailure.stdout().contains("Domain Age: unknown"), withFailure.stdout());
        assertEquals(riskScoreLine(withoutWhois.stdout()), riskScoreLine(withFailure.stdout()));
    }

    @Test
    void noWhoisFlagSkipsLookupEntirely() {
        AtomicInteger calls = new AtomicInteger();
        Captured result = runMainWithWhois(registryReporting(10, calls),
                "--url", "https://fresh-site.com", "--no-whois");

        assertEquals(0, calls.get());
        assertFalse(result.stdout().contains("Domain Age"));
        assertFalse(result.stdout().contains("domainAgeNew"));
    }

    @Test
    void ipHostUrlsAreNotLookedUp() {
        AtomicInteger calls = new AtomicInteger();
        Captured result = runMainWithWhois(registryReporting(10, calls), "--url", "http://192.168.1.1/login");

        assertEquals(0, calls.get());
        assertFalse(result.stdout().contains("Domain Age"));
    }

    @Test
    void batchModeShowsDomainAgePerEntryAndCachesRepeatedDomains(@TempDir Path tempDir) throws Exception {
        Path urls = tempDir.resolve("urls.txt");
        Files.writeString(urls, "https://fresh-site.com/a\nhttps://www.fresh-site.com/b\n", StandardCharsets.UTF_8);
        AtomicInteger calls = new AtomicInteger();

        Captured result = runMainWithWhois(registryReporting(10, calls), "--batch", urls.toString());

        assertEquals(2, countOccurrences(result.stdout(), "Domain Age: 10 days"), result.stdout());
        assertEquals(1, calls.get(), "same registrable domain should only be looked up once per run");
    }

    @Test
    void domainAgeIsWrittenToHistoryAndHtmlReport(@TempDir Path tempDir) throws Exception {
        Path history = tempDir.resolve("history.csv");
        Path report = tempDir.resolve("report.html");

        runMainWithWhois(registryReporting(10, new AtomicInteger()), "--url", "https://fresh-site.com",
                "--history-file", history.toString(), "--html-report", report.toString());

        List<String> lines = Files.readAllLines(history, StandardCharsets.UTF_8);
        assertTrue(lines.get(1).endsWith("domainAgeNew,10"), lines.get(1));
        String html = Files.readString(report, StandardCharsets.UTF_8);
        assertTrue(html.contains("<th>Domain Age</th>"));
        assertTrue(html.contains("<td>10 days</td>"), html);
    }

    @Test
    void helpListsNoWhoisOption() {
        Captured result = runMain("--help");
        assertTrue(result.stdout().contains("--no-whois"));
        assertTrue(result.stdout().contains("Network options:"));
    }

    private static String riskScoreLine(String stdout) {
        return stdout.lines().filter(l -> l.startsWith("Risk Score:")).findFirst().orElse("");
    }

    private static int countOccurrences(String haystack, String needle) {
        int count = 0;
        for (int i = haystack.indexOf(needle); i >= 0; i = haystack.indexOf(needle, i + 1)) {
            count++;
        }
        return count;
    }
}
