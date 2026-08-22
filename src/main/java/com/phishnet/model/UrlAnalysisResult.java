package com.phishnet.model;

import java.util.Collections;
import java.util.List;

/**
 * The output of {@code UrlAnalyzer#analyze(String)}: the parsed URL plus every
 * risk signal detected in it. Contains no score - scoring is the job of
 * {@code RiskScorer}.
 */
public final class UrlAnalysisResult {

    private final UrlComponents components;
    private final List<Signal> signals;

    public UrlAnalysisResult(UrlComponents components, List<Signal> signals) {
        this.components = components;
        this.signals = Collections.unmodifiableList(signals);
    }

    public UrlComponents components() {
        return components;
    }

    public List<Signal> signals() {
        return signals;
    }
}
