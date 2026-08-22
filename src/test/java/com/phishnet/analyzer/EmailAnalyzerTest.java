package com.phishnet.analyzer;

import com.phishnet.model.EmailAnalysisResult;
import com.phishnet.model.Signal;
import com.phishnet.util.ConfigLoader;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class EmailAnalyzerTest {

    private final EmailAnalyzer analyzer =
            new EmailAnalyzer(ConfigLoader.loadDefault(), new UrlAnalyzer(ConfigLoader.loadDefault()));

    private static Set<String> ids(EmailAnalysisResult result) {
        return result.signals().stream().map(Signal::id).collect(Collectors.toSet());
    }

    private static InputStream fixture(String name) throws IOException {
        Path path = Path.of("src/test/resources/emails", name);
        return Files.newInputStream(path);
    }

    @Test
    void legitimateEmailHasNoSignals() throws IOException {
        try (InputStream in = fixture("legitimate.eml")) {
            EmailAnalysisResult result = analyzer.analyze(in);

            assertEquals("alice@example.com", result.senderAddress());
            assertEquals("Lunch tomorrow?", result.subject());
            assertTrue(result.signals().isEmpty());
        }
    }

    @Test
    void displayNameBrandMismatchWithSenderDomainIsFlagged() throws IOException {
        try (InputStream in = fixture("phishing_sender_mismatch.eml")) {
            EmailAnalysisResult result = analyzer.analyze(in);

            assertEquals("PayPal Security", result.displayName());
            assertEquals("alert@random-mailer.info", result.senderAddress());
            assertTrue(ids(result).contains("senderMismatch"));
        }
    }

    @Test
    void englishUrgencyLanguageIsFlagged() throws IOException {
        try (InputStream in = fixture("phishing_urgency_en.eml")) {
            EmailAnalysisResult result = analyzer.analyze(in);
            assertTrue(ids(result).contains("urgencyLanguage"));
        }
    }

    @Test
    void turkishUrgencyLanguageIsFlagged() throws IOException {
        try (InputStream in = fixture("phishing_urgency_tr.eml")) {
            EmailAnalysisResult result = analyzer.analyze(in);
            assertTrue(ids(result).contains("urgencyLanguage"));
        }
    }

    @Test
    void ipAddressLinkInPlainTextBodyIsFlaggedAsRiskyEmbeddedLink() throws IOException {
        try (InputStream in = fixture("phishing_ip_link.eml")) {
            EmailAnalysisResult result = analyzer.analyze(in);

            assertTrue(ids(result).contains("riskyEmbeddedLink"));
            assertEquals(1, result.linkResults().size());
            assertTrue(result.linkResults().get(0).components().isIpHost());
        }
    }

    @Test
    void shortenerLinkInHtmlBodyIsExtractedAndFlagged() throws IOException {
        try (InputStream in = fixture("phishing_html_shortener.eml")) {
            EmailAnalysisResult result = analyzer.analyze(in);

            assertTrue(ids(result).contains("riskyEmbeddedLink"));
            assertTrue(result.linkResults().stream()
                    .anyMatch(r -> r.signals().stream().anyMatch(s -> s.id().equals("urlShortener"))));
        }
    }

    @Test
    void allSignalsIncludesBothEmailAndLinkSignals() throws IOException {
        try (InputStream in = fixture("phishing_ip_link.eml")) {
            EmailAnalysisResult result = analyzer.analyze(in);

            Set<String> allIds = result.allSignals().stream().map(Signal::id).collect(Collectors.toSet());
            assertTrue(allIds.contains("riskyEmbeddedLink"));
            assertTrue(allIds.contains("ipAddressHost"));
        }
    }

    @Test
    void missingFromAndSubjectHeadersDoNotThrow() throws IOException {
        try (InputStream in = fixture("missing_headers.eml")) {
            EmailAnalysisResult result = analyzer.analyze(in);

            assertEquals("", result.displayName());
            assertEquals("", result.senderAddress());
            assertEquals("", result.subject());
        }
    }

    @Test
    void emptyMessageDoesNotThrow() {
        InputStream in = new ByteArrayInputStream(new byte[0]);
        EmailAnalysisResult result = analyzer.analyze(in);

        assertEquals("", result.senderAddress());
        assertTrue(result.linkResults().isEmpty());
    }

    @Test
    void malformedContentDoesNotThrow() {
        String malformed = "This is not a valid MIME message at all, just raw bytes.\n\nNo headers here.";
        InputStream in = new ByteArrayInputStream(malformed.getBytes(StandardCharsets.UTF_8));

        EmailAnalysisResult result = analyzer.analyze(in);

        assertFalse(result.signals() == null);
    }

    @Test
    void noEmbeddedLinksMeansEmptyLinkResults() throws IOException {
        try (InputStream in = fixture("legitimate.eml")) {
            EmailAnalysisResult result = analyzer.analyze(in);
            assertTrue(result.linkResults().isEmpty());
        }
    }
}
