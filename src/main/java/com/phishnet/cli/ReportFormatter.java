package com.phishnet.cli;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.phishnet.i18n.Messages;
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
        Messages msg = Messages.current();
        StringBuilder sb = new StringBuilder();
        sb.append(msg.get("report.target", label)).append('\n');
        sb.append(msg.get("report.riskScore", score.score(), msg.get("risk." + score.level().name()))).append('\n');
        if (score.signals().isEmpty()) {
            sb.append(msg.get("report.signals.none")).append('\n');
        } else {
            sb.append(msg.get("report.signals")).append('\n');
            for (Signal signal : score.signals()) {
                sb.append("  - [").append(signal.id()).append("] ").append(signal.description(msg));
                if (!signal.evidence().isEmpty()) {
                    sb.append(" (").append(signal.evidence()).append(")");
                }
                sb.append('\n');
            }
        }
        sb.append(msg.get("report.recommendation", score.recommendation(msg))).append('\n');
        return sb.toString();
    }

    public String json(String label, RiskScore score) {
        return writeJson(toMap(label, score, Messages.current()));
    }

    public String jsonBatch(List<AnalysisEntry> entries) {
        List<Map<String, Object>> asMaps = new ArrayList<>();
        for (AnalysisEntry entry : entries) {
            asMaps.add(toMap(entry.label(), entry.score(), Messages.current()));
        }
        return writeJson(asMaps);
    }

    /**
     * The JSON structure for one result (target, score, level, recommendation, signals),
     * as a mutable ordered map. Public so the REST API can build on the exact same
     * shape the --json flag prints, adding its own fields on top.
     */
    public static Map<String, Object> toMap(String label, RiskScore score) {
        return toMap(label, score, Messages.english());
    }

    /**
     * Same, with the recommendation and signal descriptions in {@code messages}' language.
     * Keys and the level/category values are always English.
     */
    public static Map<String, Object> toMap(String label, RiskScore score, Messages messages) {
        Map<String, Object> root = new LinkedHashMap<>();
        root.put("target", label);
        root.put("score", score.score());
        root.put("level", score.level().name());
        root.put("recommendation", score.recommendation(messages));

        List<Map<String, Object>> signals = new ArrayList<>();
        for (Signal signal : score.signals()) {
            Map<String, Object> signalMap = new LinkedHashMap<>();
            signalMap.put("id", signal.id());
            signalMap.put("category", signal.category().name());
            signalMap.put("description", signal.description(messages));
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
