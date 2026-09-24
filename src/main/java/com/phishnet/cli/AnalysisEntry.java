package com.phishnet.cli;

import com.phishnet.model.DomainAgeResult;
import com.phishnet.model.RiskScore;

/**
 * One labeled analysis result: a scanned URL or email, the {@link RiskScore} it
 * produced, what kind of target it was, and its WHOIS domain age (SKIPPED when
 * no lookup was done). Shared by batch reporting/JSON output, scan history, and
 * the HTML report - all three render from this same record rather than each
 * keeping their own copy of "what was scanned."
 */
public record AnalysisEntry(String label, RiskScore score, HistoryWriter.TargetType type,
                            DomainAgeResult domainAge) {

    public AnalysisEntry {
        domainAge = domainAge == null ? DomainAgeResult.skipped() : domainAge;
    }

    public AnalysisEntry(String label, RiskScore score, HistoryWriter.TargetType type) {
        this(label, score, type, DomainAgeResult.skipped());
    }

    /** Convenience constructor for URL targets, the only kind {@code --batch} produces. */
    public AnalysisEntry(String label, RiskScore score) {
        this(label, score, HistoryWriter.TargetType.URL);
    }
}
