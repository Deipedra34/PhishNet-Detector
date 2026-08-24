package com.phishnet.cli;

import com.phishnet.analyzer.UrlAnalyzer;
import com.phishnet.model.EmailAnalysisResult;
import com.phishnet.model.RiskLevel;
import com.phishnet.model.RiskScore;
import com.phishnet.model.Signal;
import com.phishnet.model.SignalCategory;
import com.phishnet.model.UrlAnalysisResult;
import com.phishnet.util.AnsiColor;
import com.phishnet.util.ConfigLoader;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ReporterTest {

    private final UrlAnalyzer urlAnalyzer = new UrlAnalyzer(ConfigLoader.loadDefault());

    private static PrintStream capture(ByteArrayOutputStream buffer) {
        return new PrintStream(buffer, true, StandardCharsets.UTF_8);
    }

    private static List<String> lines(ByteArrayOutputStream buffer) {
        String text = buffer.toString(StandardCharsets.UTF_8).strip();
        return text.isEmpty() ? List.of() : List.of(text.split("\\r?\\n"));
    }

    private static RiskScore highScore() {
        return new RiskScore(87, RiskLevel.HIGH, List.of(
                new Signal("typosquatting", SignalCategory.URL, "Domain resembles brand 'paypal'", "edit distance 1")),
                "High risk of phishing.");
    }

    // --- quiet ---------------------------------------------------------------

    @Test
    void quietPrintsExactlyOneLine() {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        Reporter reporter = new Reporter(capture(buffer), OutputLevel.QUIET, true);
        UrlAnalysisResult result = urlAnalyzer.analyze("https://paypa1-secure-login.com");

        reporter.reportUrl("https://paypa1-secure-login.com", result, highScore());

        assertEquals(1, lines(buffer).size());
    }

    @Test
    void quietLineFormatIsLevelScoreTarget() {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        Reporter reporter = new Reporter(capture(buffer), OutputLevel.QUIET, false);
        UrlAnalysisResult result = urlAnalyzer.analyze("https://paypa1-secure-login.com");

        reporter.reportUrl("https://paypa1-secure-login.com", result, highScore());

        assertEquals("HIGH 87 https://paypa1-secure-login.com", lines(buffer).get(0));
    }

    @Test
    void quietNeverContainsAnsiCodesEvenWhenColorRequested() {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        // colorEnabled=true is requested here on purpose - Reporter must still suppress it in QUIET.
        Reporter reporter = new Reporter(capture(buffer), OutputLevel.QUIET, true);
        UrlAnalysisResult result = urlAnalyzer.analyze("https://paypa1-secure-login.com");

        reporter.reportUrl("https://paypa1-secure-login.com", result, highScore());

        assertEquals(-1, buffer.toString(StandardCharsets.UTF_8).indexOf(''));
    }

    // --- normal vs verbose ----------------------------------------------------

    @Test
    void verbosePrintsMoreLinesThanNormalForUrl() {
        UrlAnalysisResult result = urlAnalyzer.analyze("https://paypa1-secure-login.com");
        RiskScore score = highScore();

        ByteArrayOutputStream normalBuffer = new ByteArrayOutputStream();
        new Reporter(capture(normalBuffer), OutputLevel.NORMAL, false)
                .reportUrl("https://paypa1-secure-login.com", result, score);

        ByteArrayOutputStream verboseBuffer = new ByteArrayOutputStream();
        new Reporter(capture(verboseBuffer), OutputLevel.VERBOSE, false)
                .reportUrl("https://paypa1-secure-login.com", result, score);

        assertTrue(lines(verboseBuffer).size() > lines(normalBuffer).size());
    }

    @Test
    void verboseUrlOutputIncludesParsedComponents() {
        UrlAnalysisResult result = urlAnalyzer.analyze("https://paypa1-secure-login.com/verify");
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();

        new Reporter(capture(buffer), OutputLevel.VERBOSE, false)
                .reportUrl("https://paypa1-secure-login.com/verify", result, highScore());

        String text = buffer.toString(StandardCharsets.UTF_8);
        assertTrue(text.contains("Details:"));
        assertTrue(text.contains("host=paypa1-secure-login.com"));
    }

    @Test
    void verbosePrintsMoreLinesThanNormalForEmail() {
        EmailAnalysisResult result = new EmailAnalysisResult(
                "PayPal Security", "alert@random-mailer.info", "", "Account Alert",
                List.of(urlAnalyzer.analyze("http://192.168.1.1/login")),
                List.of(new Signal("senderMismatch", SignalCategory.EMAIL, "Display name mismatch", "evidence")));
        RiskScore score = highScore();

        ByteArrayOutputStream normalBuffer = new ByteArrayOutputStream();
        new Reporter(capture(normalBuffer), OutputLevel.NORMAL, false)
                .reportEmail("phish.eml", result, score);

        ByteArrayOutputStream verboseBuffer = new ByteArrayOutputStream();
        new Reporter(capture(verboseBuffer), OutputLevel.VERBOSE, false)
                .reportEmail("phish.eml", result, score);

        assertTrue(lines(verboseBuffer).size() > lines(normalBuffer).size());
    }

    @Test
    void verboseEmailOutputListsInspectedLinks() {
        EmailAnalysisResult result = new EmailAnalysisResult(
                "PayPal Security", "alert@random-mailer.info", "", "Account Alert",
                List.of(urlAnalyzer.analyze("http://192.168.1.1/login")),
                List.of());
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();

        new Reporter(capture(buffer), OutputLevel.VERBOSE, false).reportEmail("phish.eml", result, highScore());

        String text = buffer.toString(StandardCharsets.UTF_8);
        assertTrue(text.contains("Links inspected (1)"));
        assertTrue(text.contains("192.168.1.1"));
        assertTrue(text.contains("alert@random-mailer.info"));
    }

    @Test
    void normalUrlOutputDoesNotIncludeDetailsSection() {
        UrlAnalysisResult result = urlAnalyzer.analyze("https://paypa1-secure-login.com");
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();

        new Reporter(capture(buffer), OutputLevel.NORMAL, false)
                .reportUrl("https://paypa1-secure-login.com", result, highScore());

        assertFalse(buffer.toString(StandardCharsets.UTF_8).contains("Details:"));
    }

    // --- color -----------------------------------------------------------------

    @Test
    void colorEnabledIncludesAnsiCodesInNormalOutput() {
        UrlAnalysisResult result = urlAnalyzer.analyze("https://paypa1-secure-login.com");
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();

        new Reporter(capture(buffer), OutputLevel.NORMAL, true)
                .reportUrl("https://paypa1-secure-login.com", result, highScore());

        assertTrue(buffer.toString(StandardCharsets.UTF_8).contains(AnsiColor.RED.code()));
    }

    @Test
    void colorDisabledHasNoAnsiCodesInNormalOutput() {
        UrlAnalysisResult result = urlAnalyzer.analyze("https://paypa1-secure-login.com");
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();

        new Reporter(capture(buffer), OutputLevel.NORMAL, false)
                .reportUrl("https://paypa1-secure-login.com", result, highScore());

        assertEquals(-1, buffer.toString(StandardCharsets.UTF_8).indexOf(''));
    }

    @Test
    void lowRiskUsesGreenAndCheckmarkWhenNoSignals() {
        UrlAnalysisResult result = urlAnalyzer.analyze("https://example.com");
        RiskScore clean = new RiskScore(0, RiskLevel.LOW, List.of(), "No strong indicators.");
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();

        new Reporter(capture(buffer), OutputLevel.NORMAL, true).reportUrl("https://example.com", result, clean);

        String text = buffer.toString(StandardCharsets.UTF_8);
        assertTrue(text.contains(AnsiColor.GREEN.code()));
        assertTrue(text.contains("✓"));
    }

    @Test
    void mediumRiskUsesYellowWarningSymbol() {
        UrlAnalysisResult result = urlAnalyzer.analyze("http://free-prize.tk");
        RiskScore medium = new RiskScore(45, RiskLevel.MEDIUM, List.of(
                new Signal("suspiciousTld", SignalCategory.URL, "Bad TLD", ".tk")), "Proceed with caution.");
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();

        new Reporter(capture(buffer), OutputLevel.NORMAL, true).reportUrl("http://free-prize.tk", result, medium);

        String text = buffer.toString(StandardCharsets.UTF_8);
        assertTrue(text.contains(AnsiColor.YELLOW.code()));
        assertTrue(text.contains("⚠"));
    }

    @Test
    void highRiskUsesRedFailureSymbol() {
        UrlAnalysisResult result = urlAnalyzer.analyze("https://paypa1-secure-login.com");
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();

        new Reporter(capture(buffer), OutputLevel.NORMAL, true)
                .reportUrl("https://paypa1-secure-login.com", result, highScore());

        String text = buffer.toString(StandardCharsets.UTF_8);
        assertTrue(text.contains(AnsiColor.RED.code()));
        assertTrue(text.contains("✗"));
    }

    // --- batch -------------------------------------------------------------

    @Test
    void batchQuietPrintsOneLinePerEntryAndNoSummary() {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        Reporter reporter = new Reporter(capture(buffer), OutputLevel.QUIET, false);

        reporter.reportBatchEntry(new AnalysisEntry("https://a.com",
                new RiskScore(0, RiskLevel.LOW, List.of(), "ok")));
        reporter.reportBatchEntry(new AnalysisEntry("http://192.168.1.1",
                highScore()));
        reporter.reportBatchSummary(2, 1, 0);

        List<String> outputLines = lines(buffer);
        assertEquals(2, outputLines.size());
        assertEquals("LOW 0 https://a.com", outputLines.get(0));
        assertEquals("HIGH 87 http://192.168.1.1", outputLines.get(1));
    }

    @Test
    void batchNormalIncludesSummaryLine() {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        Reporter reporter = new Reporter(capture(buffer), OutputLevel.NORMAL, false);

        reporter.reportBatchSummary(3, 1, 1);

        assertTrue(buffer.toString(StandardCharsets.UTF_8).contains("Summary: 3 URL(s) analyzed - 1 high risk, 1 medium risk"));
    }
}
