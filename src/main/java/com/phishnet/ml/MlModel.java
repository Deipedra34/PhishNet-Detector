package com.phishnet.ml;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.IOException;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Clock;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;

/**
 * A trained {@link LogisticRegression} plus what's worth knowing about how it was
 * made (when, from which dataset, how many examples), and its on-disk JSON form.
 *
 * <p>The file stores the feature names it was trained with. Loading a file whose
 * feature list doesn't match {@link FeatureVector#NAMES} (e.g. one written by a
 * different PhishNet version) fails like any other invalid file, rather than
 * silently applying weights to the wrong inputs.
 */
public final class MlModel {

    static final String FORMAT = "phishnet-ml-model";
    static final int FORMAT_VERSION = 1;
    static final String ALGORITHM = "logistic-regression";

    private static final ObjectMapper MAPPER = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);

    private final LogisticRegression classifier;
    private final Instant trainedAt;
    private final String dataset;
    private final int datasetSize;
    private final int phishingExamples;
    private final double trainingAccuracy;

    MlModel(LogisticRegression classifier, Instant trainedAt, String dataset, int datasetSize,
            int phishingExamples, double trainingAccuracy) {
        if (classifier.featureCount() != FeatureVector.SIZE) {
            throw new IllegalArgumentException("classifier has " + classifier.featureCount()
                    + " features, expected " + FeatureVector.SIZE);
        }
        this.classifier = classifier;
        this.trainedAt = trainedAt;
        this.dataset = dataset;
        this.datasetSize = datasetSize;
        this.phishingExamples = phishingExamples;
        this.trainingAccuracy = trainingAccuracy;
    }

    /** Trains a fresh model on {@code data}, stamped with the current time. */
    public static MlModel train(TrainingData data) {
        return train(data, Clock.systemUTC());
    }

    static MlModel train(TrainingData data, Clock clock) {
        List<double[]> rows = new ArrayList<>(data.size());
        boolean[] labels = new boolean[data.size()];
        for (int i = 0; i < data.size(); i++) {
            rows.add(data.examples().get(i).features().toArray());
            labels[i] = data.examples().get(i).phishing();
        }
        LogisticRegression classifier = LogisticRegression.train(rows, labels);

        int correct = 0;
        for (int i = 0; i < rows.size(); i++) {
            if ((classifier.probability(rows.get(i)) >= 0.5) == labels[i]) {
                correct++;
            }
        }
        return new MlModel(classifier, clock.instant().truncatedTo(ChronoUnit.SECONDS), data.source(), data.size(),
                (int) data.phishingCount(), (double) correct / data.size());
    }

    /** Phishing probability, 0.0-1.0. */
    public double probability(FeatureVector features) {
        return classifier.probability(features.toArray());
    }

    public LogisticRegression classifier() {
        return classifier;
    }

    public String algorithm() {
        return ALGORITHM;
    }

    public Instant trainedAt() {
        return trainedAt;
    }

    /** Where the training data came from: "bundled training-data.csv" or the file path given to {@code --data}. */
    public String dataset() {
        return dataset;
    }

    public int datasetSize() {
        return datasetSize;
    }

    public int phishingExamples() {
        return phishingExamples;
    }

    public int legitimateExamples() {
        return datasetSize - phishingExamples;
    }

    /** Fraction of the training examples the model classifies correctly (at a 0.5 threshold). */
    public double trainingAccuracy() {
        return trainingAccuracy;
    }

    public int featureCount() {
        return FeatureVector.SIZE;
    }

    // --- persistence ----------------------------------------------------------

    /** Writes the model as JSON, creating parent directories; replaces any existing file in one step. */
    public void save(Path file) throws IOException {
        Path parent = file.toAbsolutePath().getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }
        // Write a sibling temp file first so a crash (or a concurrent first-use
        // training in another process) never leaves a half-written model behind.
        Path temp = Files.createTempFile(parent, file.getFileName().toString(), ".tmp");
        try {
            MAPPER.writeValue(temp.toFile(), toJson());
            try {
                Files.move(temp, file, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            } catch (AtomicMoveNotSupportedException e) {
                Files.move(temp, file, StandardCopyOption.REPLACE_EXISTING);
            }
        } finally {
            Files.deleteIfExists(temp);
        }
    }

    /**
     * @throws IOException if the file can't be read, isn't valid JSON, or isn't a
     *                     complete model for the current feature set
     */
    public static MlModel load(Path file) throws IOException {
        JsonNode root;
        try {
            root = MAPPER.readTree(file.toFile());
        } catch (JsonProcessingException e) {
            // getOriginalMessage() leaves out Jackson's multi-line source-location suffix.
            throw new IOException("not valid JSON: " + e.getOriginalMessage(), e);
        }
        try {
            return fromJson(root);
        } catch (IllegalArgumentException e) {
            throw new IOException("invalid model file: " + e.getMessage(), e);
        }
    }

    ObjectNode toJson() {
        ObjectNode root = MAPPER.createObjectNode();
        root.put("format", FORMAT);
        root.put("formatVersion", FORMAT_VERSION);
        root.put("algorithm", ALGORITHM);
        root.put("trainedAt", trainedAt.toString());
        root.put("dataset", dataset);
        root.put("datasetSize", datasetSize);
        root.put("phishingExamples", phishingExamples);
        root.put("legitimateExamples", legitimateExamples());
        root.put("trainingAccuracy", trainingAccuracy);
        ArrayNode features = root.putArray("features");
        FeatureVector.NAMES.forEach(features::add);
        putArray(root, "means", classifier.means());
        putArray(root, "stdDevs", classifier.stdDevs());
        putArray(root, "weights", classifier.weights());
        root.put("bias", classifier.bias());
        return root;
    }

    static MlModel fromJson(JsonNode root) {
        if (root == null || !root.isObject()) {
            throw new IllegalArgumentException("not a JSON object");
        }
        if (!FORMAT.equals(text(root, "format"))) {
            throw new IllegalArgumentException("not a PhishNet model file");
        }
        int version = integer(root, "formatVersion");
        if (version != FORMAT_VERSION) {
            throw new IllegalArgumentException("unsupported formatVersion " + version);
        }
        if (!ALGORITHM.equals(text(root, "algorithm"))) {
            throw new IllegalArgumentException("unsupported algorithm '" + text(root, "algorithm") + "'");
        }
        JsonNode features = root.get("features");
        List<String> names = new ArrayList<>();
        if (features != null && features.isArray()) {
            features.forEach(f -> names.add(f.asText()));
        }
        if (!names.equals(FeatureVector.NAMES)) {
            throw new IllegalArgumentException("model features " + names + " don't match this version's "
                    + FeatureVector.NAMES + " - retrain it");
        }
        Instant trainedAt;
        try {
            trainedAt = Instant.parse(text(root, "trainedAt"));
        } catch (DateTimeParseException e) {
            throw new IllegalArgumentException("'trainedAt' is not an ISO-8601 instant");
        }
        int datasetSize = integer(root, "datasetSize");
        int phishing = integer(root, "phishingExamples");
        if (datasetSize < 0 || phishing < 0 || phishing > datasetSize) {
            throw new IllegalArgumentException("inconsistent dataset counts");
        }
        LogisticRegression classifier = new LogisticRegression(
                doubles(root, "means"), doubles(root, "stdDevs"), doubles(root, "weights"), number(root, "bias"));
        return new MlModel(classifier, trainedAt, text(root, "dataset"), datasetSize, phishing,
                number(root, "trainingAccuracy"));
    }

    private static void putArray(ObjectNode root, String field, double[] values) {
        ArrayNode array = root.putArray(field);
        for (double v : values) {
            array.add(v);
        }
    }

    private static String text(JsonNode root, String field) {
        JsonNode node = root.get(field);
        if (node == null || !node.isTextual()) {
            throw new IllegalArgumentException("missing or non-text field '" + field + "'");
        }
        return node.asText();
    }

    private static int integer(JsonNode root, String field) {
        JsonNode node = root.get(field);
        if (node == null || !node.canConvertToInt() || !node.isIntegralNumber()) {
            throw new IllegalArgumentException("missing or non-integer field '" + field + "'");
        }
        return node.asInt();
    }

    private static double number(JsonNode root, String field) {
        JsonNode node = root.get(field);
        if (node == null || !node.isNumber()) {
            throw new IllegalArgumentException("missing or non-numeric field '" + field + "'");
        }
        return node.asDouble();
    }

    private static double[] doubles(JsonNode root, String field) {
        JsonNode node = root.get(field);
        if (node == null || !node.isArray() || node.size() != FeatureVector.SIZE) {
            throw new IllegalArgumentException("field '" + field + "' must be an array of "
                    + FeatureVector.SIZE + " numbers");
        }
        double[] values = new double[node.size()];
        for (int i = 0; i < values.length; i++) {
            if (!node.get(i).isNumber()) {
                throw new IllegalArgumentException("field '" + field + "' must contain only numbers");
            }
            values[i] = node.get(i).asDouble();
        }
        return values;
    }
}
