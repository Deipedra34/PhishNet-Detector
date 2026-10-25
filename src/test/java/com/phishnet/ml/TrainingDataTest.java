package com.phishnet.ml;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TrainingDataTest {

    private static final String HEADER = String.join(",", FeatureVector.NAMES) + ",label";

    private static TrainingData parse(String csv) throws IOException {
        return TrainingData.parse(new StringReader(csv), "test.csv");
    }

    private static String message(String csv) {
        return assertThrows(IllegalArgumentException.class, () -> parse(csv)).getMessage();
    }

    @Test
    void parsesRowsSkippingCommentsAndBlankLines() throws IOException {
        TrainingData data = parse("# a comment\n\n" + HEADER + "\n"
                + "39,1,1,0,0,1,1,0,0,0,26,0,1\n"
                + "# another comment\n"
                + "29,0,2,1,0,10,0,0,0,0,9000,1,0\n");

        assertEquals("test.csv", data.source());
        assertEquals(2, data.size());
        assertEquals(1, data.phishingCount());
        assertEquals(1, data.legitimateCount());
        assertTrue(data.examples().get(0).phishing());
        assertEquals(39, data.examples().get(0).features().get("url_length"));
        assertEquals(9000, data.examples().get(1).features().get("domain_age_days"));
    }

    @Test
    void emptyCellMeansUnknown() throws IOException {
        TrainingData data = parse(HEADER + "\n31,1,3,0,1,10,0,0,0,0,,0,1\n29,0,2,1,0,10,0,0,0,0,9000,1,0\n");

        assertTrue(Double.isNaN(data.examples().get(0).features().get("domain_age_days")));
    }

    @Test
    void columnsMayBeReorderedAndExtraColumnsAreIgnored() throws IOException {
        String header = "label,notes," + String.join(",", FeatureVector.NAMES.reversed());
        TrainingData data = parse(header + "\n"
                + "1,0,0,26,0,0,0,1,1,0,0,1,1,39\n"
                + "0,0,1,9000,0,0,0,0,10,0,1,2,0,29\n");

        FeatureVector first = data.examples().get(0).features();
        assertEquals(39, first.get("url_length"));
        assertEquals(26, first.get("domain_age_days"));
        assertEquals(0, first.get("https"));
        assertTrue(data.examples().get(0).phishing());
        assertFalse(data.examples().get(1).phishing());
    }

    @Test
    void rejectsMalformedData() {
        assertTrue(message(HEADER.replace("https,", "") + "\n").contains("missing column 'https'"));
        assertTrue(message(String.join(",", FeatureVector.NAMES) + "\n").contains("missing column 'label'"));
        assertTrue(message(HEADER + "\n1,2,3\n").contains("line 2: expected 13 columns"));
        assertTrue(message(HEADER + "\n39,x,1,0,0,1,1,0,0,0,26,0,1\n").contains("'special_chars' is not a number"));
        assertTrue(message(HEADER + "\n39,NaN,1,0,0,1,1,0,0,0,26,0,1\n").contains("is not a number"));
        assertTrue(message(HEADER + "\n39,1,1,0,0,1,1,0,0,0,26,0,yes\n").contains("label must be 1"));
        assertTrue(message("# only comments\n").contains("no header row"));
    }

    @Test
    void rejectsDataWithOnlyOneClass() {
        String message = message(HEADER + "\n39,1,1,0,0,1,1,0,0,0,26,0,1\n40,1,1,0,0,1,1,0,0,0,26,0,1\n");

        assertTrue(message.contains("at least one phishing (1) and one legitimate (0)"), message);
    }

    @Test
    void loadsFromFile(@TempDir Path tempDir) throws IOException {
        Path file = tempDir.resolve("data.csv");
        Files.writeString(file, "\uFEFF" + HEADER + "\n39,1,1,0,0,1,1,0,0,0,26,0,1\n29,0,2,1,0,10,0,0,0,0,9000,1,0\n",
                StandardCharsets.UTF_8);

        TrainingData data = TrainingData.load(file);

        assertEquals(file.toString(), data.source());
        assertEquals(2, data.size());
    }

    @Test
    void bundledDatasetLoadsWithBothClasses() throws IOException {
        TrainingData data = TrainingData.bundled();

        assertEquals(TrainingData.BUNDLED_SOURCE, data.source());
        assertTrue(data.size() >= 50, "bundled dataset should have a few dozen rows at least");
        assertTrue(data.phishingCount() >= 20);
        assertTrue(data.legitimateCount() >= 20);
    }
}
