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

    @Test
    void helpFlagPrintsUsageAndExitsZero() {
        Captured result = runMain("--help");
        assertEquals(0, result.exitCode());
        assertTrue(result.stdout().contains("Usage:"));
    }

    @Test
    void noModeFlagPrintsErrorAndUsage() {
        Captured result = runMain("--json");
        assertEquals(2, result.exitCode());
        assertTrue(result.stderr().contains("Error"));
        assertTrue(result.stderr().contains("Usage:"));
    }

    @Test
    void unknownFlagIsRejected() {
        Captured result = runMain("--nope");
        assertEquals(2, result.exitCode());
        assertTrue(result.stderr().contains("Unknown argument"));
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
}
