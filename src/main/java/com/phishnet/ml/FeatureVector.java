package com.phishnet.ml;

import java.util.Arrays;
import java.util.List;

/**
 * The fixed-length numeric view of one scanned URL that the ML layer works on.
 * Built by {@link FeatureExtractor} from what the analyzers already produced, or
 * read straight from a row of the training CSV - both use {@link #NAMES} as the
 * column order, so a model trained on one can score the other.
 *
 * A value of {@link Double#NaN} means "unknown" (e.g. domain age when WHOIS was
 * skipped or failed). The classifier treats unknown as neutral rather than as zero.
 */
public final class FeatureVector {

    /** Feature names, in vector order. Also the training CSV column names and the model file's feature list. */
    public static final List<String> NAMES = List.of(
            "url_length",
            "special_chars",
            "dot_count",
            "subdomain_count",
            "ip_host",
            "brand_distance",
            "typosquatting",
            "homograph",
            "suspicious_tld",
            "url_shortener",
            "domain_age_days",
            "https");

    public static final int SIZE = NAMES.size();

    private final double[] values;

    /**
     * @param values exactly {@link #SIZE} values in {@link #NAMES} order; NaN marks an unknown value
     * @throws IllegalArgumentException on a wrong length or an infinite value
     */
    public FeatureVector(double[] values) {
        if (values.length != SIZE) {
            throw new IllegalArgumentException("expected " + SIZE + " feature values, got " + values.length);
        }
        for (int i = 0; i < SIZE; i++) {
            if (Double.isInfinite(values[i])) {
                throw new IllegalArgumentException("feature " + NAMES.get(i) + " is infinite");
            }
        }
        this.values = values.clone();
    }

    public double get(int index) {
        return values[index];
    }

    /** @throws IllegalArgumentException if {@code name} isn't one of {@link #NAMES} */
    public double get(String name) {
        int index = NAMES.indexOf(name);
        if (index < 0) {
            throw new IllegalArgumentException("unknown feature: " + name);
        }
        return values[index];
    }

    public boolean isUnknown(int index) {
        return Double.isNaN(values[index]);
    }

    public double[] toArray() {
        return values.clone();
    }

    /** {@code name=value} pairs, whole numbers without a decimal point and unknown values as {@code ?}. */
    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < SIZE; i++) {
            if (i > 0) {
                sb.append(", ");
            }
            sb.append(NAMES.get(i)).append('=').append(format(values[i]));
        }
        return sb.toString();
    }

    static String format(double value) {
        if (Double.isNaN(value)) {
            return "?";
        }
        if (value == Math.rint(value)) {
            return Long.toString((long) value);
        }
        return Double.toString(value);
    }

    @Override
    public boolean equals(Object o) {
        // Arrays.equals compares doubles bitwise, so two NaN (unknown) values count as equal.
        return o instanceof FeatureVector other && Arrays.equals(values, other.values);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(values);
    }
}
