package com.phishnet.analyzer;

import com.phishnet.model.UrlAnalysisResult;
import com.phishnet.util.ConfigLoader;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Exercises {@link UrlAnalyzer} against real-world-style URL lists (not just
 * synthetic one-off examples): a batch of known phishing patterns that should
 * each raise at least one signal, and a batch of ordinary legitimate URLs
 * that should raise none.
 */
class UrlFixtureTest {

    private final UrlAnalyzer analyzer = new UrlAnalyzer(ConfigLoader.loadDefault());

    private static List<String> readUrls(String fileName) throws IOException {
        Path path = Path.of("src/test/resources/urls", fileName);
        return Files.readAllLines(path).stream()
                .map(String::trim)
                .filter(line -> !line.isEmpty() && !line.startsWith("#"))
                .toList();
    }

    @Test
    void everyPhishingFixtureRaisesAtLeastOneSignal() throws IOException {
        for (String url : readUrls("phishing_urls.txt")) {
            UrlAnalysisResult result = analyzer.analyze(url);
            assertTrue(!result.signals().isEmpty(), "Expected at least one signal for: " + url);
        }
    }

    @Test
    void everyLegitimateFixtureRaisesNoSignal() throws IOException {
        for (String url : readUrls("legitimate_urls.txt")) {
            UrlAnalysisResult result = analyzer.analyze(url);
            assertTrue(result.signals().isEmpty(),
                    "Expected no signals for: " + url + " but got: " + result.signals());
        }
    }
}
