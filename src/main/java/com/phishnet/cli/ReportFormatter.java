package com.phishnet.cli;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.phishnet.model.RiskScore;
import com.phishnet.model.Signal;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Renders a RiskScore as either a human-readable report or JSON (for
 * --json / CI use). Model classes have no Jackson annotations on them, so
 * this just builds the map structure by hand before handing it to the
 * ObjectMapper.
 */
public final class ReportFormatter {

    private final ObjectMapper mapper;

    public ReportFormatter() {
        this.mapper = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);
    }

    public String humanReadable(String label, RiskScore score) {
        StringBuilder sb = new StringBuilder();
        sb.append("Target: ").append(label).append('\n');
        sb.append("Risk Score: ").append(score.score()).append("/100 (").append(score.level()).append(")\n");
        if (score.signals().isEmpty()) {
            sb.append("Signals: none\n");
        } else {
            sb.append("Signals:\n");
            for (Signal signal : score.signals()) {
                sb.append("  - [").append(signal.id()).append("] ").append(signal.description());
                if (!signal.evidence().isEmpty()) {
                    sb.append(" (").append(signal.evidence()).append(")");
                }
                sb.append('\n');
            }
        }
        sb.append("Recommendation: ").append(score.recommendation()).append('\n');
        return sb.toString();
    }

    public String json(String label, RiskScore score) {
        return writeJson(toMap(label, score));
    }

    public String jsonBatch(List<AnalysisEntry> entries) {
        List<Map<String, Object>> asMaps = new ArrayList<>();
        for (AnalysisEntry entry : entries) {
            asMaps.add(toMap(entry.label(), entry.score()));
        }
        return writeJson(asMaps);
    }

    private static Map<String, Object> toMap(String label, RiskScore score) {
        Map<String, Object> root = new LinkedHashMap<>();
        root.put("target", label);
        root.put("score", score.score());
        root.put("level", score.level().name());
        root.put("recommendation", score.recommendation());

        List<Map<String, Object>> signals = new ArrayList<>();
        for (Signal signal : score.signals()) {
            Map<String, Object> signalMap = new LinkedHashMap<>();
            signalMap.put("id", signal.id());
            signalMap.put("category", signal.category().name());
            signalMap.put("description", signal.description());
            signalMap.put("evidence", signal.evidence());
            signals.add(signalMap);
        }
        root.put("signals", signals);
        return root;
    }

    private String writeJson(Object value) {
        try {
            return mapper.writeValueAsString(value);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Failed to serialize report to JSON", e);
        }
    }
}
