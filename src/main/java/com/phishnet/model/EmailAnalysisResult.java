package com.phishnet.model;

import java.util.Collections;
import java.util.List;

/**
 * The output of {@code EmailAnalyzer}: parsed sender/subject info, every
 * embedded link's own analysis, and the signals raised at the email level
 * (urgency language, sender spoofing, risky embedded links).
 */
public final class EmailAnalysisResult {

    private final String displayName;
    private final String senderAddress;
    private final String replyToAddress;
    private final String subject;
    private final List<UrlAnalysisResult> linkResults;
    private final List<Signal> signals;

    public EmailAnalysisResult(String displayName, String senderAddress, String replyToAddress, String subject,
                                List<UrlAnalysisResult> linkResults, List<Signal> signals) {
        this.displayName = displayName == null ? "" : displayName;
        this.senderAddress = senderAddress == null ? "" : senderAddress;
        this.replyToAddress = replyToAddress == null ? "" : replyToAddress;
        this.subject = subject == null ? "" : subject;
        this.linkResults = Collections.unmodifiableList(linkResults);
        this.signals = Collections.unmodifiableList(signals);
    }

    public String displayName() {
        return displayName;
    }

    public String senderAddress() {
        return senderAddress;
    }

    public String replyToAddress() {
        return replyToAddress;
    }

    public String subject() {
        return subject;
    }

    public List<UrlAnalysisResult> linkResults() {
        return linkResults;
    }

    public List<Signal> signals() {
        return signals;
    }

    /** All signals: this email's own, plus every signal raised by its embedded links. */
    public List<Signal> allSignals() {
        List<Signal> all = new java.util.ArrayList<>(signals);
        for (UrlAnalysisResult link : linkResults) {
            all.addAll(link.signals());
        }
        return all;
    }
}
