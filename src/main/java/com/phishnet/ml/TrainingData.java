package com.phishnet.ml;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

/**
 * A labeled training set for the ML layer, read from CSV.
 *
 * <p>Format: blank lines and lines starting with {@code #} are ignored; the first
 * remaining line is a header naming the columns. It must include every
 * {@link FeatureVector#NAMES feature} plus {@code label} ({@code 1} = phishing,
 * {@code 0} = legitimate), in any order; any other column is ignored. An empty
 * feature cell means "unknown" (e.g. no domain age). Values are plain numbers -
 * there's no quoting, since no column holds text.
 *
 * @param source  where the data came from, for display ("bundled training-data.csv" or a file path)
 * @param examples the parsed rows, in file order
 */
public record TrainingData(String source, List<Example> examples) {

    /** Classpath location of the dataset that ships inside the jar. */
    public static final String BUNDLED_RESOURCE = "/training-data.csv";
    public static final String BUNDLED_SOURCE = "bundled training-data.csv";

    static final String LABEL_COLUMN = "label";

    /** One labeled row. */
    public record Example(FeatureVector features, boolean phishing) {
    }

    public TrainingData {
        examples = Collections.unmodifiableList(new ArrayList<>(examples));
    }

    /** The dataset bundled in the jar. */
    public static TrainingData bundled() throws IOException {
        InputStream in = TrainingData.class.getResourceAsStream(BUNDLED_RESOURCE);
        if (in == null) {
            throw new IOException("bundled training data " + BUNDLED_RESOURCE + " is missing from the classpath");
        }
        try (Reader reader = new InputStreamReader(in, StandardCharsets.UTF_8)) {
            return parse(reader, BUNDLED_SOURCE);
        }
    }

    /** A user-supplied CSV file. */
    public static TrainingData load(Path file) throws IOException {
        try (Reader reader = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
            return parse(reader, file.toString());
        }
    }

    /**
     * @param source where the data came from, recorded as {@link #source()}
     * @throws IllegalArgumentException with the offending line number if the CSV is malformed,
     *                                  or if it doesn't contain both phishing and legitimate rows
     */
    public static TrainingData parse(Reader reader, String source) throws IOException {
        // Read it all up front (training files are small) rather than wrapping the
        // caller's reader in a BufferedReader that this method would never close.
        StringWriter text = new StringWriter();
        reader.transferTo(text);
        List<String> lines = text.toString().lines().toList();

        int[] featureColumns = null;
        int labelColumn = -1;
        int columnCount = 0;
        List<Example> examples = new ArrayList<>();

        for (int index = 0; index < lines.size(); index++) {
            int lineNumber = index + 1;
            String trimmed = lines.get(index).strip();
            if (lineNumber == 1 && trimmed.startsWith("\uFEFF")) {
                trimmed = trimmed.substring(1).strip(); // UTF-8 byte order mark from some spreadsheet exports
            }
            if (trimmed.isEmpty() || trimmed.startsWith("#")) {
                continue;
            }
            String[] cells = trimmed.split(",", -1);

            if (featureColumns == null) {
                List<String> header = Arrays.stream(cells).map(c -> c.strip().toLowerCase(Locale.ROOT)).toList();
                featureColumns = new int[FeatureVector.SIZE];
                for (int i = 0; i < FeatureVector.SIZE; i++) {
                    featureColumns[i] = header.indexOf(FeatureVector.NAMES.get(i));
                    if (featureColumns[i] < 0) {
                        throw error(lineNumber, "header is missing column '" + FeatureVector.NAMES.get(i) + "'");
                    }
                }
                labelColumn = header.indexOf(LABEL_COLUMN);
                if (labelColumn < 0) {
                    throw error(lineNumber, "header is missing column '" + LABEL_COLUMN + "'");
                }
                columnCount = cells.length;
                continue;
            }

            if (cells.length != columnCount) {
                throw error(lineNumber, "expected " + columnCount + " columns, found " + cells.length);
            }
            double[] values = new double[FeatureVector.SIZE];
            for (int i = 0; i < FeatureVector.SIZE; i++) {
                values[i] = parseValue(cells[featureColumns[i]].strip(), FeatureVector.NAMES.get(i), lineNumber);
            }
            String label = cells[labelColumn].strip();
            if (!label.equals("0") && !label.equals("1")) {
                throw error(lineNumber, "label must be 1 (phishing) or 0 (legitimate), found '" + label + "'");
            }
            examples.add(new Example(new FeatureVector(values), label.equals("1")));
        }

        if (featureColumns == null) {
            throw new IllegalArgumentException("no header row found");
        }
        TrainingData data = new TrainingData(source, examples);
        if (data.phishingCount() == 0 || data.legitimateCount() == 0) {
            throw new IllegalArgumentException("needs at least one phishing (1) and one legitimate (0) "
                    + "example, found " + data.phishingCount() + " and " + data.legitimateCount());
        }
        return data;
    }

    private static double parseValue(String cell, String column, int lineNumber) {
        if (cell.isEmpty()) {
            return Double.NaN;
        }
        try {
            double value = Double.parseDouble(cell);
            // parseDouble also accepts "NaN" and "Infinity" - only plain numbers are valid here.
            if (Double.isFinite(value)) {
                return value;
            }
        } catch (NumberFormatException ignored) {
            // reported below
        }
        throw error(lineNumber, "column '" + column + "' is not a number: '" + cell + "'");
    }

    private static IllegalArgumentException error(int lineNumber, String message) {
        return new IllegalArgumentException("line " + lineNumber + ": " + message);
    }

    public int size() {
        return examples.size();
    }

    public long phishingCount() {
        return examples.stream().filter(Example::phishing).count();
    }

    public long legitimateCount() {
        return size() - phishingCount();
    }
}
