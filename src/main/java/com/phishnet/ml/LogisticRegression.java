package com.phishnet.ml;

import java.util.Arrays;
import java.util.List;

/**
 * A plain binary logistic regression classifier, trained with full-batch gradient
 * descent and a small L2 penalty. Deliberately simple: no external ML library, no
 * randomness (weights start at zero and every pass sees every example in order), so
 * training the same data always gives the same model.
 *
 * <p>Features are standardized ({@code (x - mean) / stdDev}, with the mean and
 * standard deviation taken from the training data) before the weights are applied,
 * so each weight reads as "how much one standard deviation of this feature pushes
 * toward phishing." Unknown (NaN) values standardize to 0, i.e. the training mean,
 * which makes them neutral. Standardized values are clamped to
 * &plusmn;{@value #Z_CLAMP} so a single extreme input (a 5,000-character URL) can't
 * single-handedly saturate the output.
 */
public final class LogisticRegression {

    public static final int DEFAULT_ITERATIONS = 3000;
    public static final double DEFAULT_LEARNING_RATE = 0.1;
    public static final double DEFAULT_L2 = 0.01;

    static final double Z_CLAMP = 5.0;

    private final double[] means;
    private final double[] stdDevs;
    private final double[] weights;
    private final double bias;

    /**
     * @throws IllegalArgumentException if the arrays differ in length, any value is
     *                                  non-finite, or a standard deviation isn't positive
     */
    public LogisticRegression(double[] means, double[] stdDevs, double[] weights, double bias) {
        if (means.length != weights.length || stdDevs.length != weights.length) {
            throw new IllegalArgumentException("means, stdDevs and weights must have the same length");
        }
        for (int i = 0; i < weights.length; i++) {
            if (!Double.isFinite(means[i]) || !Double.isFinite(stdDevs[i]) || !Double.isFinite(weights[i])) {
                throw new IllegalArgumentException("model parameter " + i + " is not a finite number");
            }
            if (stdDevs[i] <= 0) {
                throw new IllegalArgumentException("stdDev " + i + " must be positive");
            }
        }
        if (!Double.isFinite(bias)) {
            throw new IllegalArgumentException("bias is not a finite number");
        }
        this.means = means.clone();
        this.stdDevs = stdDevs.clone();
        this.weights = weights.clone();
        this.bias = bias;
    }

    /** Trains with the default iteration count, learning rate, and L2 penalty. */
    public static LogisticRegression train(List<double[]> rows, boolean[] labels) {
        return train(rows, labels, DEFAULT_ITERATIONS, DEFAULT_LEARNING_RATE, DEFAULT_L2);
    }

    /**
     * @param rows   one feature array per example, all the same length (NaN = unknown)
     * @param labels {@code true} for phishing, parallel to {@code rows}
     * @throws IllegalArgumentException on empty input, mismatched lengths, or a single class only
     */
    public static LogisticRegression train(List<double[]> rows, boolean[] labels,
                                           int iterations, double learningRate, double l2) {
        int n = rows.size();
        if (n == 0) {
            throw new IllegalArgumentException("no training examples");
        }
        if (labels.length != n) {
            throw new IllegalArgumentException("got " + n + " examples but " + labels.length + " labels");
        }
        int d = rows.get(0).length;
        int positives = 0;
        for (int r = 0; r < n; r++) {
            if (rows.get(r).length != d) {
                throw new IllegalArgumentException("example " + r + " has " + rows.get(r).length
                        + " features, expected " + d);
            }
            if (labels[r]) {
                positives++;
            }
        }
        if (positives == 0 || positives == n) {
            throw new IllegalArgumentException("training data needs both phishing and legitimate examples");
        }

        double[] means = new double[d];
        double[] stdDevs = new double[d];
        for (int j = 0; j < d; j++) {
            double sum = 0;
            int count = 0;
            for (double[] row : rows) {
                if (!Double.isNaN(row[j])) {
                    sum += row[j];
                    count++;
                }
            }
            means[j] = count == 0 ? 0 : sum / count;
            double squares = 0;
            for (double[] row : rows) {
                if (!Double.isNaN(row[j])) {
                    squares += (row[j] - means[j]) * (row[j] - means[j]);
                }
            }
            double std = count == 0 ? 0 : Math.sqrt(squares / count);
            // A constant (or entirely unknown) column carries no information; a
            // stdDev of 1 just keeps the math defined and its weight near zero.
            stdDevs[j] = std > 1e-9 ? std : 1.0;
        }

        double[][] z = new double[n][];
        for (int r = 0; r < n; r++) {
            z[r] = standardize(rows.get(r), means, stdDevs);
        }

        double[] weights = new double[d];
        double bias = 0;
        double[] gradient = new double[d];
        for (int iter = 0; iter < iterations; iter++) {
            Arrays.fill(gradient, 0);
            double biasGradient = 0;
            for (int r = 0; r < n; r++) {
                double error = sigmoid(bias + dot(weights, z[r])) - (labels[r] ? 1 : 0);
                for (int j = 0; j < d; j++) {
                    gradient[j] += error * z[r][j];
                }
                biasGradient += error;
            }
            for (int j = 0; j < d; j++) {
                weights[j] -= learningRate * (gradient[j] / n + l2 * weights[j]);
            }
            bias -= learningRate * biasGradient / n;
        }
        return new LogisticRegression(means, stdDevs, weights, bias);
    }

    /** Probability (0.0-1.0) that {@code features} belongs to the phishing class. */
    public double probability(double[] features) {
        if (features.length != weights.length) {
            throw new IllegalArgumentException("expected " + weights.length + " features, got " + features.length);
        }
        return sigmoid(bias + dot(weights, standardize(features, means, stdDevs)));
    }

    public int featureCount() {
        return weights.length;
    }

    public double[] means() {
        return means.clone();
    }

    public double[] stdDevs() {
        return stdDevs.clone();
    }

    public double[] weights() {
        return weights.clone();
    }

    public double bias() {
        return bias;
    }

    private static double[] standardize(double[] x, double[] means, double[] stdDevs) {
        double[] z = new double[x.length];
        for (int j = 0; j < x.length; j++) {
            z[j] = Double.isNaN(x[j])
                    ? 0
                    : Math.max(-Z_CLAMP, Math.min(Z_CLAMP, (x[j] - means[j]) / stdDevs[j]));
        }
        return z;
    }

    private static double dot(double[] a, double[] b) {
        double sum = 0;
        for (int i = 0; i < a.length; i++) {
            sum += a[i] * b[i];
        }
        return sum;
    }

    /** Numerically stable logistic function: never overflows for large |t|. */
    static double sigmoid(double t) {
        if (t >= 0) {
            return 1 / (1 + Math.exp(-t));
        }
        double e = Math.exp(t);
        return e / (1 + e);
    }
}
