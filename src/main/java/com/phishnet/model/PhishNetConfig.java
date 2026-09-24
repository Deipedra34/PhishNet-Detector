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
        private final int domainAgeNewDays;
        private final int domainAgeRecentDays;

        public ScoringConfig(Map<String, Integer> weights, int mediumThreshold, int highThreshold,
                              int typosquattingMaxDistance, int longUrlThreshold, int maxQueryParams,
                              int encodedCharThreshold) {
            this(weights, mediumThreshold, highThreshold, typosquattingMaxDistance, longUrlThreshold,
                    maxQueryParams, encodedCharThreshold, 30, 180);
        }

        public ScoringConfig(Map<String, Integer> weights, int mediumThreshold, int highThreshold,
                              int typosquattingMaxDistance, int longUrlThreshold, int maxQueryParams,
                              int encodedCharThreshold, int domainAgeNewDays, int domainAgeRecentDays) {
            this.weights = Collections.unmodifiableMap(weights);
            this.mediumThreshold = mediumThreshold;
            this.highThreshold = highThreshold;
            this.typosquattingMaxDistance = typosquattingMaxDistance;
            this.longUrlThreshold = longUrlThreshold;
            this.maxQueryParams = maxQueryParams;
            this.encodedCharThreshold = encodedCharThreshold;
            this.domainAgeNewDays = domainAgeNewDays;
            this.domainAgeRecentDays = domainAgeRecentDays;
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

        /** A domain younger than this many days raises {@code domainAgeNew}. */
        public int domainAgeNewDays() {
            return domainAgeNewDays;
        }

        /**
         * A domain at least {@link #domainAgeNewDays()} old but no older than this many
         * days raises {@code domainAgeRecent}; anything older counts as established.
         */
        public int domainAgeRecentDays() {
            return domainAgeRecentDays;
        }

        public int weightOf(String signalId) {
            return weightOf(signalId, 10);
        }

        /** Like {@link #weightOf(String)}, but with an explicit fallback for ids missing from the config. */
        public int weightOf(String signalId, int fallback) {
            return weights.getOrDefault(signalId, fallback);
        }
    }
}
