package com.phishnet.cli;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MainTest {

    private record Captured(int exitCode, String stdout, String stderr) {
    }

    private static Captured runMain(String... args) {
        ByteArrayOutputStream outBytes = new ByteArrayOutputStream();
        ByteArrayOutputStream errBytes = new ByteArrayOutputStream();
        try (PrintStream out = new PrintStream(outBytes, true, StandardCharsets.UTF_8);
             PrintStream err = new PrintStream(errBytes, true, StandardCharsets.UTF_8)) {
            int code = Main.run(args, out, err);
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
}
