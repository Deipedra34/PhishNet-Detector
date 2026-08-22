package com.phishnet.model;

import java.util.Collections;
import java.util.List;

/**
 * The final, combined output of {@code RiskScorer}: a 0-100 score, a
 * {@link RiskLevel} label, the signals that produced it, and a short
 * human-facing recommendation.
 */
public final class RiskScore {

    private final int score;
    private final RiskLevel level;
    private final List<Signal> signals;
    private final String recommendation;

    public RiskScore(int score, RiskLevel level, List<Signal> signals, String recommendation) {
        this.score = score;
        this.level = level;
        this.signals = Collections.unmodifiableList(signals);
        this.recommendation = recommendation;
    }

    public int score() {
        return score;
    }

    public RiskLevel level() {
        return level;
    }

    public List<Signal> signals() {
        return signals;
    }

    public String recommendation() {
        return recommendation;
    }
}
