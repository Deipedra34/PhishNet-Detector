package com.phishnet.ml;

import com.phishnet.analyzer.UrlAnalyzer;
import com.phishnet.model.DomainAgeResult;
import com.phishnet.model.PhishNetConfig;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MlScorerTest {

    private static final PhishNetConfig CONFIG = PhishNetConfig.defaultConfig();
    private static final UrlAnalyzer ANALYZER = new UrlAnalyzer(CONFIG);

    private final ByteArrayOutputStream errBytes = new ByteArrayOutputStream();
    private final PrintStream err = new PrintStream(errBytes, true, StandardCharsets.UTF_8);

    private String stderr() {
        return errBytes.toString(StandardCharsets.UTF_8);
    }

    @Test
    void firstUseTrainsFromBundledDataAndSavesTheModel(@TempDir Path tempDir) {
        Path file = tempDir.resolve("sub/model.json");

        MlScorer scorer = MlScorer.open(file, CONFIG, err);

        assertTrue(scorer.isEnabled());
        assertTrue(Files.exists(file));
        assertEquals("", stderr());
        assertEquals(TrainingData.BUNDLED_SOURCE, scorer.model().dataset());
    }

    @Test
    void existingModelIsLoadedNotRetrained(@TempDir Path tempDir) throws IOException {
        Path file = tempDir.resolve("model.json");
        MlScorer.open(file, CONFIG, err);
        String saved = Files.readString(file);

        MlScorer reopened = MlScorer.open(file, CONFIG, err);

        assertTrue(reopened.isEnabled());
        assertEquals(saved, Files.readString(file), "the model file must not be rewritten on a normal load");
    }

    @Test
    void corruptModelWarnsOnceAndDisablesScoring(@TempDir Path tempDir) throws IOException {
        Path file = tempDir.resolve("model.json");
        Files.writeString(file, "{ this is not a model");

        MlScorer scorer = MlScorer.open(file, CONFIG, err);

        assertFalse(scorer.isEnabled());
        assertTrue(stderr().startsWith("Warning: ML model"), stderr());
        assertTrue(stderr().contains("phishnet model train"), stderr());
        assertEquals(1, stderr().strip().lines().count());
        assertEquals(Optional.empty(), scorer.predict(ANALYZER.analyze("http://paypa1.com"), DomainAgeResult.skipped()));
        assertTrue(scorer.probability(new FeatureVector(new double[FeatureVector.SIZE])).isEmpty());
    }

    @Test
    void unsavableModelIsStillUsedForThisRun(@TempDir Path tempDir) throws IOException {
        // A regular file where the model's parent directory should be: saving must fail.
        Path blocker = tempDir.resolve("not-a-directory");
        Files.writeString(blocker, "x");
        Path file = blocker.resolve("model.json");

        MlScorer scorer = MlScorer.open(file, CONFIG, err);

        assertTrue(scorer.isEnabled());
        assertTrue(stderr().contains("could not save the ML model"), stderr());
        assertTrue(scorer.predict(ANALYZER.analyze("https://example.com"), DomainAgeResult.skipped()).isPresent());
    }

    @Test
    void disabledScorerNeverPredicts() {
        MlScorer scorer = MlScorer.disabled();

        assertFalse(scorer.isEnabled());
        assertTrue(scorer.predict(ANALYZER.analyze("http://paypa1.com"), DomainAgeResult.skipped()).isEmpty());
    }

    @Test
    void predictSkipsMalformedUrlsAndScoresValidOnes(@TempDir Path tempDir) {
        MlScorer scorer = MlScorer.open(tempDir.resolve("model.json"), CONFIG, err);

        assertTrue(scorer.predict(ANALYZER.analyze(""), DomainAgeResult.skipped()).isEmpty());

        MlPrediction prediction = scorer.predict(ANALYZER.analyze("http://paypa1.com/login"), DomainAgeResult.skipped())
                .orElseThrow();
        assertTrue(prediction.probability() >= 0 && prediction.probability() <= 1);
        assertEquals(1, prediction.features().get("typosquatting"));
        assertEquals(prediction.probability(), scorer.probability(prediction.features()).getAsDouble(), 1e-12);
    }

    @Test
    void displayPercentHedgesTheExtremes() {
        FeatureVector v = new FeatureVector(new double[FeatureVector.SIZE]);

        assertEquals("73%", new MlPrediction(0.73, v).displayPercent());
        assertEquals(">99%", new MlPrediction(0.998, v).displayPercent());
        assertEquals("<1%", new MlPrediction(0.002, v).displayPercent());
        assertEquals(73, new MlPrediction(0.734, v).percent());
    }

    @Test
    void defaultPathIsUnderTheUsersPhishnetDirectory() {
        Path path = MlScorer.defaultPath();

        assertEquals(MlScorer.DEFAULT_FILE_NAME, path.getFileName().toString());
        assertEquals(MlScorer.DEFAULT_DIRECTORY, path.getParent().getFileName().toString());
    }
}
