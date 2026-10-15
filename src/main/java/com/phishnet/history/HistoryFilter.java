package com.phishnet.history;

import com.phishnet.cli.HistoryWriter.TargetType;
import com.phishnet.model.RiskLevel;

import java.time.Instant;

/**
 * Criteria for {@link HistoryDatabase#search}. Every field is optional ({@code null}
 * = no constraint); the ones that are set are combined with AND.
 *
 * @param targetContains case-insensitive substring of the target, domain, or email subject
 * @param riskLevel      exact risk level
 * @param type           URL or EMAIL
 * @param since          earliest timestamp, inclusive
 * @param until          latest timestamp, exclusive
 * @param limit          maximum rows to return, newest first; {@code 0} for no limit
 */
public record HistoryFilter(String targetContains, RiskLevel riskLevel, TargetType type,
                            Instant since, Instant until, int limit) {

    public HistoryFilter {
        if (limit < 0) {
            throw new IllegalArgumentException("limit must be >= 0, was " + limit);
        }
        if (targetContains != null && targetContains.isEmpty()) {
            targetContains = null;
        }
    }

    /** No criteria: the {@code limit} most recent scans. */
    public static HistoryFilter recent(int limit) {
        return new HistoryFilter(null, null, null, null, null, limit);
    }
}
