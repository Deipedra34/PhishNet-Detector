package com.phishnet.model;

import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * Everything that's tunable: brand list, suspicious TLDs, URL shorteners,
 * urgency keywords per language, and the scoring weights. Normally built by
 * ConfigLoader from YAML, but it's just a plain value object so tests can
 * construct one directly without touching the filesystem.
 */
public final class PhishNetConfig {

    private final List<String> brands;
    private final List<String> suspiciousTlds;
    private final List<String> urlShorteners;
    private final Map<String, List<String>> urgencyKeywords;
    private final ScoringConfig scoring;

    public PhishNetConfig(List<String> brands, List<String> suspiciousTlds, List<String> urlShorteners,
                           Map<String, List<String>> urgencyKeywords, ScoringConfig scoring) {
        this.brands = Collections.unmodifiableList(brands);
        this.suspiciousTlds = Collections.unmodifiableList(suspiciousTlds);
        this.urlShorteners = Collections.unmodifiableList(urlShorteners);
        this.urgencyKeywords = Collections.unmodifiableMap(urgencyKeywords);
        this.scoring = scoring;
    }

    public List<String> brands() {
        return brands;
    }

    public List<String> suspiciousTlds() {
        return suspiciousTlds;
    }

    public List<String> urlShorteners() {
        return urlShorteners;
    }

    public Map<String, List<String>> urgencyKeywords() {
        return urgencyKeywords;
    }

    public ScoringConfig scoring() {
        return scoring;
    }

    /** A reasonable, self-contained configuration used as a fallback and in tests. */
    public static PhishNetConfig defaultConfig() {
        return com.phishnet.util.ConfigLoader.loadDefault();
    }

    /** Weighted scoring configuration: per-signal weights and score-band thresholds. */
    public static final class ScoringConfig {
        private final Map<String, Integer> weights;
        private final int mediumThreshold;
        private final int highThreshold;
        private final int typosquattingMaxDistance;
        private final int longUrlThreshold;
        private final int maxQueryParams;
        private final int encodedCharThreshold;

        public ScoringConfig(Map<String, Integer> weights, int mediumThreshold, int highThreshold,
                              int typosquattingMaxDistance, int longUrlThreshold, int maxQueryParams,
                              int encodedCharThreshold) {
            this.weights = Collections.unmodifiableMap(weights);
            this.mediumThreshold = mediumThreshold;
            this.highThreshold = highThreshold;
            this.typosquattingMaxDistance = typosquattingMaxDistance;
            this.longUrlThreshold = longUrlThreshold;
            this.maxQueryParams = maxQueryParams;
            this.encodedCharThreshold = encodedCharThreshold;
        }

        public Map<String, Integer> weights() {
            return weights;
        }

        /** Minimum total score (inclusive) classified as {@link RiskLevel#MEDIUM}. */
        public int mediumThreshold() {
            return mediumThreshold;
        }

        /** Minimum total score (inclusive) classified as {@link RiskLevel#HIGH}. */
        public int highThreshold() {
            return highThreshold;
        }

        public int typosquattingMaxDistance() {
            return typosquattingMaxDistance;
        }

        public int longUrlThreshold() {
            return longUrlThreshold;
        }

        public int maxQueryParams() {
            return maxQueryParams;
        }

        /** Minimum count of percent-encoded ({@code %XX}) sequences in a URL to flag it as obfuscated. */
        public int encodedCharThreshold() {
            return encodedCharThreshold;
        }

        public int weightOf(String signalId) {
            return weights.getOrDefault(signalId, 10);
        }
    }
}
