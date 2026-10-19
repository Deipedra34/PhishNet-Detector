package com.phishnet.cli;

import com.phishnet.analyzer.WhoisClient;
import com.phishnet.ml.FeatureVector;
import com.phishnet.ml.MlModel;
import com.phishnet.ml.TrainingData;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@code phishnet model train|info}, driven through {@link Main#run} like the real CLI.
 * Every test points {@code --model} into a JUnit temp directory, so the suite never
 * touches the real {@code ~/.phishnet} model.
 */
class ModelCommandTest {

    private record Captured(int exitCode, String stdout, String stderr) {
    }

    private static final WhoisClient OFFLINE_WHOIS = (server, query, timeoutMillis) -> {
        throw new IOException("network disabled in tests");
    };

    @TempDir
    Path tempDir;

    private Path modelFile;

    @BeforeEach
    void setUp() {
        modelFile = tempDir.resolve("model.json");
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

    private Captured model(String subcommand, String... options) {
        String[] args = new String[options.length + 4];
        args[0] = "model";
        args[1] = subcommand;
        args[2] = "--model";
        args[3] = modelFile.toString();
        System.arraycopy(options, 0, args, 4, options.length);
        return runMain(args);
    }

    @Test
    void trainOnBundledDataSavesTheModel() throws IOException {
        Captured result = model("train");

        assertEquals(0, result.exitCode(), result.stderr());
        assertEquals("", result.stderr());
        assertTrue(Files.exists(modelFile));
        assertTrue(result.stdout().contains("Trained a logistic regression model on " + FeatureVector.SIZE + " features"),
                result.stdout());
        assertTrue(result.stdout().contains(TrainingData.BUNDLED_SOURCE));
        assertTrue(result.stdout().contains("Model saved to:"));
        assertEquals(TrainingData.bundled().size(), MlModel.load(modelFile).datasetSize());
    }

    @Test
    void trainOnUserSuppliedData() throws IOException {
        Path data = tempDir.resolve("my-data.csv");
        Files.writeString(data, String.join(",", FeatureVector.NAMES) + ",label\n"
                + "39,1,1,0,0,1,1,0,0,0,26,0,1\n"
                + "45,3,1,0,0,0,1,0,1,0,12,0,1\n"
                + "29,0,2,1,0,10,0,0,0,0,9000,1,0\n"
                + "33,0,2,1,0,10,0,0,0,0,7000,1,0\n");

        Captured result = model("train", "--data", data.toString());

        assertEquals(0, result.exitCode(), result.stderr());
        assertTrue(result.stdout().contains("4 examples (2 phishing, 2 legitimate)"), result.stdout());
        MlModel saved = MlModel.load(modelFile);
        assertEquals(data.toString(), saved.dataset());
        assertEquals(4, saved.datasetSize());
    }

    @Test
    void trainRetrainsOverAnExistingModel() throws IOException {
        Files.writeString(modelFile, "corrupt");

        Captured result = model("train");

        assertEquals(0, result.exitCode(), result.stderr());
        assertEquals(TrainingData.bundled().size(), MlModel.load(modelFile).datasetSize());
    }

    @Test
    void trainWithMissingDataFileFailsCleanly() {
        Captured result = model("train", "--data", tempDir.resolve("nope.csv").toString());

        assertEquals(1, result.exitCode());
        assertTrue(result.stderr().contains("could not load training data"), result.stderr());
        assertTrue(result.stderr().contains("file not found"), result.stderr());
        assertFalse(Files.exists(modelFile));
    }

    @Test
    void trainWithInvalidDataReportsTheLine() throws IOException {
        Path data = tempDir.resolve("bad.csv");
        Files.writeString(data, String.join(",", FeatureVector.NAMES) + ",label\n39,1,1,0,0,1,1,0,0,0,26,0,maybe\n");

        Captured result = model("train", "--data", data.toString());

        assertEquals(1, result.exitCode());
        assertTrue(result.stderr().contains("line 2"), result.stderr());
        assertFalse(Files.exists(modelFile));
    }

    @Test
    void infoShowsModelDetails() {
        model("train");

        Captured result = model("info");

        assertEquals(0, result.exitCode(), result.stderr());
        String out = result.stdout();
        assertTrue(out.contains("Model file:        " + modelFile), out);
        assertTrue(out.contains("Algorithm:         logistic regression"), out);
        assertTrue(out.contains("Trained:"), out);
        assertTrue(out.contains("Dataset size:"), out);
        assertTrue(out.contains("Features (" + FeatureVector.SIZE + "):"), out);
        for (String name : FeatureVector.NAMES) {
            assertTrue(out.contains(name), name);
        }
    }

    @Test
    void infoWithoutAModelExplainsHowToGetOne() {
        Captured result = model("info");

        assertEquals(0, result.exitCode());
        assertTrue(result.stdout().contains("No trained model"), result.stdout());
        assertTrue(result.stdout().contains("phishnet model train"));
        assertFalse(Files.exists(modelFile), "info must never create a model");
    }

    @Test
    void infoOnCorruptModelFails() throws IOException {
        Files.writeString(modelFile, "{ broken");

        Captured result = model("info");

        assertEquals(1, result.exitCode());
        assertTrue(result.stderr().contains("could not read model file"), result.stderr());
        assertTrue(result.stderr().contains("phishnet model train"));
    }

    @Test
    void missingSubcommandIsAUsageError() {
        Captured result = runMain("model");

        assertEquals(2, result.exitCode());
        assertTrue(result.stderr().contains("Missing required command: train or info"), result.stderr());
    }

    @Test
    void helpListsBothSubcommands() {
        Captured result = runMain("model", "--help");

        assertEquals(0, result.exitCode());
        assertTrue(result.stdout().contains("train"));
        assertTrue(result.stdout().contains("info"));
    }
}
