package com.phishnet.cli;

import com.phishnet.model.RiskLevel;
import com.phishnet.model.RiskScore;
import com.phishnet.model.Signal;
import com.phishnet.model.SignalCategory;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertTrue;

class ReportFormatterTest {

    private final ReportFormatter formatter = new ReportFormatter();

    @Test
    void humanReadableIncludesScoreLevelAndRecommendation() {
        RiskScore score = new RiskScore(72, RiskLevel.HIGH, List.of(
                new Signal("homograph", SignalCategory.URL, "Domain mixes scripts", "xn--evil")),
                "High risk of phishing.");

        String report = formatter.humanReadable("http://example.com", score);

        assertTrue(report.contains("http://example.com"));
        assertTrue(report.contains("72/100"));
        assertTrue(report.contains("HIGH"));
        assertTrue(report.contains("homograph"));
        assertTrue(report.contains("xn--evil"));
        assertTrue(report.contains("High risk of phishing."));
    }

    @Test
    void humanReadableWithNoSignalsSaysNone() {
        RiskScore score = new RiskScore(0, RiskLevel.LOW, List.of(), "No strong indicators.");
        String report = formatter.humanReadable("http://example.com", score);
        assertTrue(report.contains("Signals: none"));
    }

    @Test
    void jsonContainsScoreLevelAndSignalFields() {
        RiskScore score = new RiskScore(45, RiskLevel.MEDIUM, List.of(
                new Signal("suspiciousTld", SignalCategory.URL, "Bad TLD", ".tk")),
                "Proceed with caution.");

        String json = formatter.json("http://example.tk", score);

        assertTrue(json.contains("\"target\""));
        assertTrue(json.contains("\"score\" : 45") || json.contains("\"score\":45"));
        assertTrue(json.contains("MEDIUM"));
        assertTrue(json.contains("suspiciousTld"));
        assertTrue(json.contains(".tk"));
    }

    @Test
    void jsonBatchProducesArrayOfEntries() {
        RiskScore first = new RiskScore(0, RiskLevel.LOW, List.of(), "ok");
        RiskScore second = new RiskScore(80, RiskLevel.HIGH, List.of(
                new Signal("ipAddressHost", SignalCategory.URL, "IP host")), "danger");

        String json = formatter.jsonBatch(List.of(
                new AnalysisEntry("http://a.com", first),
                new AnalysisEntry("http://192.168.1.1", second)));

        assertTrue(json.trim().startsWith("["));
        assertTrue(json.contains("http://a.com"));
        assertTrue(json.contains("http://192.168.1.1"));
        assertTrue(json.contains("ipAddressHost"));
    }
}
