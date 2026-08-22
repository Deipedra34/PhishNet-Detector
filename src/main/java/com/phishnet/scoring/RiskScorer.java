package com.phishnet.scoring;

import com.phishnet.model.PhishNetConfig;
import com.phishnet.model.RiskLevel;
import com.phishnet.model.RiskScore;
import com.phishnet.model.Signal;

import java.util.List;

/**
 * Turns whatever signals the analyzers raised into a single 0-100 score and
 * a RiskLevel label. Weights and thresholds only live here - analyzers just
 * report what they found, they don't assign points.
 *
 * No parsing, no certificate checks, no email handling in this class on
 * purpose, so it can be tested with hand-built signal lists.
 */
public final class RiskScorer {

    private final PhishNetConfig config;

    public RiskScorer(PhishNetConfig config) {
        this.config = config;
    }

    /**
     * Scores a combined list of signals from one or more analyzers. Weight
     * lookup is by signal id; if the same id shows up twice (e.g. two risky
     * links in one email) it counts twice. Clamps to 0-100, then maps to a
     * RiskLevel via the configured thresholds.
     */
    public RiskScore score(List<Signal> signals) {
        var scoring = config.scoring();

        int total = 0;
        for (Signal signal : signals) {
            total += scoring.weightOf(signal.id());
        }
        int clamped = Math.max(0, Math.min(100, total));

        RiskLevel level;
        if (clamped >= scoring.highThreshold()) {
            level = RiskLevel.HIGH;
        } else if (clamped >= scoring.mediumThreshold()) {
            level = RiskLevel.MEDIUM;
        } else {
            level = RiskLevel.LOW;
        }

        return new RiskScore(clamped, level, signals, recommendationFor(level));
    }

    private static String recommendationFor(RiskLevel level) {
        switch (level) {
            case HIGH:
                return "High risk of phishing. Do not click any links, enter credentials, or open attachments. "
                        + "Report and delete.";
            case MEDIUM:
                return "Some phishing indicators found. Proceed with caution: verify the sender/domain through "
                        + "a separate trusted channel before interacting.";
            case LOW:
            default:
                return "No strong phishing indicators found. Still verify anything requesting credentials "
                        + "or payment before acting on it.";
        }
    }
}
