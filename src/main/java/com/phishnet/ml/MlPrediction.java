package com.phishnet.ml;

/**
 * The ML layer's opinion on one URL: a phishing probability and the features it was
 * computed from. An additional signal shown next to the rule-based {@code RiskScore},
 * never a replacement for it.
 */
public record MlPrediction(double probability, FeatureVector features) {

    /** The probability as a whole percentage, 0-100. */
    public int percent() {
        return (int) Math.round(probability * 100);
    }

    /**
     * The percentage for display: "73%", but "&gt;99%" / "&lt;1%" at the extremes, since a
     * model trained on a small dataset is never actually certain.
     */
    public String displayPercent() {
        if (probability > 0.99) {
            return ">99%";
        }
        if (probability < 0.01) {
            return "<1%";
        }
        return percent() + "%";
    }
}
