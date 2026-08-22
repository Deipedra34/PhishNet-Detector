package com.phishnet.cli;

import com.phishnet.model.RiskScore;

/** One labeled analysis result, as produced for a single URL in {@code --batch} mode. */
public record AnalysisEntry(String label, RiskScore score) {
}
