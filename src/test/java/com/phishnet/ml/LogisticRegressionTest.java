package com.phishnet.ml;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Asserts only directional behavior (which side of 0.5 a prediction lands on, which
 * of two inputs scores higher), never exact probabilities.
 */
class LogisticRegressionTest {

    /**
     * Two obviously separable classes: phishing rows have a high first feature and a
     * low second one, legitimate rows the opposite. A third feature is pure noise.
     */
    private static LogisticRegression trainSeparable() {
        List<double[]> rows = new ArrayList<>();
        List<Boolean> labels = new ArrayList<>();
        for (int i = 0; i < 20; i++) {
            double jitter = (i % 5) * 0.3;
            rows.add(new double[] {8 + jitter, 1 + jitter, i % 3});
            labels.add(true);
            rows.add(new double[] {1 + jitter, 9 - jitter, i % 3});
            labels.add(false);
        }
        boolean[] y = new boolean[labels.size()];
        for (int i = 0; i < y.length; i++) {
            y[i] = labels.get(i);
        }
        return LogisticRegression.train(rows, y);
    }

    @Test
    void classifiesHeldOutExamplesOnTheCorrectSide() {
        LogisticRegression model = trainSeparable();

        assertTrue(model.probability(new double[] {9, 0.5, 1}) > 0.5);
        assertTrue(model.probability(new double[] {7.5, 2, 0}) > 0.5);
        assertTrue(model.probability(new double[] {0.5, 9.5, 2}) < 0.5);
        assertTrue(model.probability(new double[] {2, 8, 1}) < 0.5);
    }

    @Test
    void moreExtremeInputScoresMorePhishingLike() {
        LogisticRegression model = trainSeparable();

        assertTrue(model.probability(new double[] {9, 1, 1}) > model.probability(new double[] {5, 5, 1}));
        assertTrue(model.probability(new double[] {5, 5, 1}) > model.probability(new double[] {1, 9, 1}));
    }

    @Test
    void learnedWeightsPointTheRightWay() {
        double[] w = trainSeparable().weights();

        assertTrue(w[0] > 0, "high first feature means phishing");
        assertTrue(w[1] < 0, "high second feature means legitimate");
        assertTrue(Math.abs(w[2]) < Math.abs(w[0]), "noise feature should matter less than a real one");
    }

    @Test
    void probabilitiesStayWithinZeroAndOneEvenForExtremeInput() {
        LogisticRegression model = trainSeparable();

        for (double[] x : List.of(new double[] {1e9, -1e9, 0}, new double[] {-1e9, 1e9, 0}, new double[3])) {
            double p = model.probability(x);
            assertTrue(p >= 0 && p <= 1, "p=" + p);
        }
    }

    @Test
    void unknownValuesAreTreatedAsNeutral() {
        LogisticRegression model = trainSeparable();

        double unknownFirst = model.probability(new double[] {Double.NaN, 5, 1});
        assertTrue(unknownFirst < model.probability(new double[] {9, 5, 1}));
        assertTrue(unknownFirst > model.probability(new double[] {1, 5, 1}));
    }

    @Test
    void trainingIsDeterministic() {
        LogisticRegression a = trainSeparable();
        LogisticRegression b = trainSeparable();

        assertArrayEquals(a.weights(), b.weights());
        assertEquals(a.bias(), b.bias());
    }

    @Test
    void rejectsInvalidTrainingInput() {
        List<double[]> rows = List.of(new double[] {1, 2}, new double[] {3, 4});

        assertThrows(IllegalArgumentException.class,
                () -> LogisticRegression.train(List.of(), new boolean[0]));
        assertThrows(IllegalArgumentException.class,
                () -> LogisticRegression.train(rows, new boolean[] {true}));
        assertThrows(IllegalArgumentException.class,
                () -> LogisticRegression.train(rows, new boolean[] {true, true}), "single class only");
        assertThrows(IllegalArgumentException.class,
                () -> LogisticRegression.train(List.of(new double[] {1, 2}, new double[] {3}), new boolean[] {true, false}));
    }

    @Test
    void rejectsInvalidParametersAndWrongInputLength() {
        double[] ones = {1, 1};
        assertThrows(IllegalArgumentException.class,
                () -> new LogisticRegression(ones, new double[] {1, 0}, ones, 0), "stdDev must be positive");
        assertThrows(IllegalArgumentException.class,
                () -> new LogisticRegression(ones, ones, new double[] {1, Double.NaN}, 0));
        assertThrows(IllegalArgumentException.class,
                () -> new LogisticRegression(ones, ones, new double[] {1}, 0));

        LogisticRegression model = new LogisticRegression(ones, ones, ones, 0);
        assertThrows(IllegalArgumentException.class, () -> model.probability(new double[] {1}));
    }

    @Test
    void sigmoidIsStableAtTheExtremes() {
        assertEquals(0.5, LogisticRegression.sigmoid(0), 1e-12);
        assertEquals(1.0, LogisticRegression.sigmoid(1000), 1e-12);
        assertEquals(0.0, LogisticRegression.sigmoid(-1000), 1e-12);
    }
}
