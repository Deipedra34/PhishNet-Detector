package com.phishnet.scoring;

import com.phishnet.model.PhishNetConfig;
import com.phishnet.model.PhishNetConfig.ScoringConfig;
import com.phishnet.model.RiskLevel;
import com.phishnet.model.RiskScore;
import com.phishnet.model.Signal;
import com.phishnet.model.SignalCategory;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RiskScorerTest {

    private static PhishNetConfig configWithWeights(Map<String, Integer> weights, int mediumThreshold, int highThreshold) {
        ScoringConfig scoring = new ScoringConfig(weights, mediumThreshold, highThreshold, 2, 75, 8, 5);
        return new PhishNetConfig(List.of(), List.of(), List.of(), Map.of(), scoring);
    }

    @Test
    void noSignalsProducesZeroScoreAndLowRisk() {
        RiskScorer scorer = new RiskScorer(configWithWeights(Map.of(), 30, 60));
        RiskScore result = scorer.score(List.of());

        assertEquals(0, result.score());
        assertEquals(RiskLevel.LOW, result.level());
    }

    @Test
    void singleSignalContributesItsConfiguredWeight() {
        RiskScorer scorer = new RiskScorer(configWithWeights(Map.of("ipAddressHost", 25), 30, 60));
        RiskScore result = scorer.score(List.of(
                new Signal("ipAddressHost", SignalCategory.URL, "IP host")));

        assertEquals(25, result.score());
        assertEquals(RiskLevel.LOW, result.level());
    }

    @Test
    void multipleSignalsSumTheirWeights() {
        RiskScorer scorer = new RiskScorer(configWithWeights(
                Map.of("homograph", 35, "typosquatting", 30), 30, 60));
        RiskScore result = scorer.score(List.of(
                new Signal("homograph", SignalCategory.URL, "homograph"),
                new Signal("typosquatting", SignalCategory.URL, "typo")));

        assertEquals(65, result.score());
        assertEquals(RiskLevel.HIGH, result.level());
    }

    @Test
    void repeatedSignalIdContributesEachOccurrence() {
        RiskScorer scorer = new RiskScorer(configWithWeights(Map.of("riskyEmbeddedLink", 15), 30, 60));
        RiskScore result = scorer.score(List.of(
                new Signal("riskyEmbeddedLink", SignalCategory.EMAIL, "link 1"),
                new Signal("riskyEmbeddedLink", SignalCategory.EMAIL, "link 2"),
                new Signal("riskyEmbeddedLink", SignalCategory.EMAIL, "link 3")));

        assertEquals(45, result.score());
        assertEquals(RiskLevel.MEDIUM, result.level());
    }

    @Test
    void scoreIsClampedAtOneHundred() {
        RiskScorer scorer = new RiskScorer(configWithWeights(Map.of("homograph", 60), 30, 60));
        RiskScore result = scorer.score(List.of(
                new Signal("homograph", SignalCategory.URL, "a"),
                new Signal("homograph", SignalCategory.URL, "b"),
                new Signal("homograph", SignalCategory.URL, "c")));

        assertEquals(100, result.score());
        assertEquals(RiskLevel.HIGH, result.level());
    }

    @Test
    void unknownSignalIdFallsBackToDefaultWeightOfTen() {
        RiskScorer scorer = new RiskScorer(configWithWeights(Map.of(), 30, 60));
        RiskScore result = scorer.score(List.of(
                new Signal("somethingNotInConfig", SignalCategory.URL, "mystery signal")));

        assertEquals(10, result.score());
    }

    @Test
    void scoreExactlyAtMediumThresholdIsMedium() {
        RiskScorer scorer = new RiskScorer(configWithWeights(Map.of("suspiciousTld", 30), 30, 60));
        RiskScore result = scorer.score(List.of(new Signal("suspiciousTld", SignalCategory.URL, "tld")));

        assertEquals(30, result.score());
        assertEquals(RiskLevel.MEDIUM, result.level());
    }

    @Test
    void scoreExactlyAtHighThresholdIsHigh() {
        RiskScorer scorer = new RiskScorer(configWithWeights(Map.of("homograph", 60), 30, 60));
        RiskScore result = scorer.score(List.of(new Signal("homograph", SignalCategory.URL, "x")));

        assertEquals(60, result.score());
        assertEquals(RiskLevel.HIGH, result.level());
    }

    @Test
    void oneBelowMediumThresholdIsLow() {
        RiskScorer scorer = new RiskScorer(configWithWeights(Map.of("suspiciousTld", 29), 30, 60));
        RiskScore result = scorer.score(List.of(new Signal("suspiciousTld", SignalCategory.URL, "tld")));

        assertEquals(RiskLevel.LOW, result.level());
    }

    @Test
    void oneBelowHighThresholdIsMedium() {
        RiskScorer scorer = new RiskScorer(configWithWeights(Map.of("typosquatting", 59), 30, 60));
        RiskScore result = scorer.score(List.of(new Signal("typosquatting", SignalCategory.URL, "typo")));

        assertEquals(59, result.score());
        assertEquals(RiskLevel.MEDIUM, result.level());
    }

    @Test
    void scoreOneAboveMediumThresholdIsMedium() {
        RiskScorer scorer = new RiskScorer(configWithWeights(Map.of("suspiciousTld", 31), 30, 60));
        RiskScore result = scorer.score(List.of(new Signal("suspiciousTld", SignalCategory.URL, "tld")));

        assertEquals(RiskLevel.MEDIUM, result.level());
    }

    @Test
    void negativeConfiguredWeightClampsScoreToZeroNotBelow() {
        RiskScorer scorer = new RiskScorer(configWithWeights(Map.of("someSignal", -50), 30, 60));
        RiskScore result = scorer.score(List.of(new Signal("someSignal", SignalCategory.URL, "x")));

        assertEquals(0, result.score());
        assertEquals(RiskLevel.LOW, result.level());
    }

    @Test
    void emptySignalListOnZeroThresholdsIsStillHandled() {
        // Degenerate config where even zero signals clears the (0) medium threshold.
        RiskScorer scorer = new RiskScorer(configWithWeights(Map.of(), 0, 60));
        RiskScore result = scorer.score(List.of());

        assertEquals(0, result.score());
        assertEquals(RiskLevel.MEDIUM, result.level());
    }

    @Test
    void recommendationTextDiffersByLevel() {
        RiskScorer scorer = new RiskScorer(configWithWeights(Map.of("homograph", 60), 30, 60));
        RiskScore high = scorer.score(List.of(new Signal("homograph", SignalCategory.URL, "x")));
        RiskScore low = scorer.score(List.of());

        assertFalse(high.recommendation().isBlank());
        assertFalse(low.recommendation().isBlank());
        assertTrue(high.recommendation().toLowerCase(java.util.Locale.ROOT).contains("high")
                || !high.recommendation().equals(low.recommendation()));
    }

    @Test
    void resultRetainsOriginalSignalList() {
        RiskScorer scorer = new RiskScorer(configWithWeights(Map.of("ipAddressHost", 25), 30, 60));
        Signal signal = new Signal("ipAddressHost", SignalCategory.URL, "IP host");
        RiskScore result = scorer.score(List.of(signal));

        assertEquals(List.of(signal), result.signals());
    }
}
