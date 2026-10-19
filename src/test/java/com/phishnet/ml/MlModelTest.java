package com.phishnet.ml;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.phishnet.analyzer.UrlAnalyzer;
import com.phishnet.model.DomainAgeResult;
import com.phishnet.model.PhishNetConfig;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MlModelTest {

    private static final PhishNetConfig CONFIG = PhishNetConfig.defaultConfig();
    private static final UrlAnalyzer ANALYZER = new UrlAnalyzer(CONFIG);
    private static final FeatureExtractor EXTRACTOR = new FeatureExtractor(CONFIG);
    private static final Instant TRAINED_AT = Instant.parse("2026-10-19T12:00:00Z");

    private static MlModel bundledModel;

    @BeforeAll
    static void trainOnce() throws IOException {
        bundledModel = MlModel.train(TrainingData.bundled(), Clock.fixed(TRAINED_AT, ZoneOffset.UTC));
    }

    private static double probability(String url, long ageDays) {
        DomainAgeResult age = ageDays < 0
                ? DomainAgeResult.skipped()
                : DomainAgeResult.known("x", LocalDate.of(2026, 1, 1), ageDays, "whois.example");
        return bundledModel.probability(EXTRACTOR.extract(ANALYZER.analyze(url), age));
    }

    @Test
    void recordsTrainingMetadata() throws IOException {
        TrainingData data = TrainingData.bundled();

        assertEquals(TRAINED_AT, bundledModel.trainedAt());
        assertEquals(TrainingData.BUNDLED_SOURCE, bundledModel.dataset());
        assertEquals(data.size(), bundledModel.datasetSize());
        assertEquals(data.phishingCount(), bundledModel.phishingExamples());
        assertEquals(data.legitimateCount(), bundledModel.legitimateExamples());
        assertEquals(FeatureVector.SIZE, bundledModel.featureCount());
        assertTrue(bundledModel.trainingAccuracy() > 0.8, "accuracy=" + bundledModel.trainingAccuracy());
    }

    @Test
    void bundledModelSeparatesObviousPhishingFromObviousLegitimate() {
        assertTrue(probability("http://paypa1-secure-login.tk/verify?redirect=http://evil.tk/x", 3) > 0.5);
        assertTrue(probability("http://192.168.1.1/wp-login.php", -1) > 0.5);
        assertTrue(probability("https://www.google.com/search?q=phishnet", 9000) < 0.5);
        assertTrue(probability("https://github.com/", 6000) < 0.5);
    }

    @Test
    void youngerDomainScoresMorePhishingLikeAllElseEqual() {
        String url = "https://shop.example.com/cart";
        assertTrue(probability(url, 5) > probability(url, 5000));
    }

    @Test
    void saveAndLoadRoundTripPreservesEverything(@TempDir Path tempDir) throws IOException {
        Path file = tempDir.resolve("nested/dir/model.json");
        bundledModel.save(file);

        MlModel loaded = MlModel.load(file);

        assertEquals(bundledModel.trainedAt(), loaded.trainedAt());
        assertEquals(bundledModel.dataset(), loaded.dataset());
        assertEquals(bundledModel.datasetSize(), loaded.datasetSize());
        assertEquals(bundledModel.phishingExamples(), loaded.phishingExamples());
        assertEquals(bundledModel.trainingAccuracy(), loaded.trainingAccuracy());
        FeatureVector v = EXTRACTOR.extract(ANALYZER.analyze("http://paypa1.com/login"), DomainAgeResult.skipped());
        assertEquals(bundledModel.probability(v), loaded.probability(v), 1e-12);
        try (var files = Files.list(file.getParent())) {
            assertEquals(1, files.count(), "no temp file left behind");
        }
    }

    @Test
    void saveReplacesAnExistingFile(@TempDir Path tempDir) throws IOException {
        Path file = tempDir.resolve("model.json");
        Files.writeString(file, "old contents");

        bundledModel.save(file);

        assertEquals(bundledModel.datasetSize(), MlModel.load(file).datasetSize());
    }

    @Test
    void loadRejectsCorruptOrIncompleteFiles(@TempDir Path tempDir) throws IOException {
        Path file = tempDir.resolve("model.json");

        Files.writeString(file, "not json at all");
        assertTrue(assertThrows(IOException.class, () -> MlModel.load(file)).getMessage().contains("not valid JSON"));

        Files.writeString(file, "[1, 2, 3]");
        assertThrows(IOException.class, () -> MlModel.load(file));

        Files.writeString(file, "{\"format\": \"something-else\"}");
        assertThrows(IOException.class, () -> MlModel.load(file));

        ObjectNode json = bundledModel.toJson();
        json.remove("weights");
        Files.writeString(file, json.toString());
        assertTrue(assertThrows(IOException.class, () -> MlModel.load(file)).getMessage().contains("weights"));
    }

    @Test
    void loadRejectsModelTrainedOnADifferentFeatureSet(@TempDir Path tempDir) throws IOException {
        Path file = tempDir.resolve("model.json");
        ObjectNode json = bundledModel.toJson();
        json.withArray("features").set(0, json.textNode("something_else"));
        Files.writeString(file, json.toString());

        String message = assertThrows(IOException.class, () -> MlModel.load(file)).getMessage();
        assertTrue(message.contains("retrain"), message);
    }

    @Test
    void loadRejectsNonFiniteOrMistypedParameters(@TempDir Path tempDir) throws IOException {
        Path file = tempDir.resolve("model.json");

        ObjectNode json = bundledModel.toJson();
        json.put("bias", "high");
        Files.writeString(file, json.toString());
        assertThrows(IOException.class, () -> MlModel.load(file));

        json = bundledModel.toJson();
        json.withArray("stdDevs").set(0, json.numberNode(0.0));
        Files.writeString(file, json.toString());
        assertThrows(IOException.class, () -> MlModel.load(file));

        json = bundledModel.toJson();
        json.put("formatVersion", 99);
        Files.writeString(file, json.toString());
        assertThrows(IOException.class, () -> MlModel.load(file));
    }
}
