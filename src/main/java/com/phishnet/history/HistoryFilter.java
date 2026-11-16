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
 * @param offset         matching rows to skip before the first one returned (for paging); {@code 0} skips none
 */
public record HistoryFilter(String targetContains, RiskLevel riskLevel, TargetType type,
                            Instant since, Instant until, int limit, int offset) {

    public HistoryFilter {
        if (limit < 0) {
            throw new IllegalArgumentException("limit must be >= 0, was " + limit);
        }
        if (offset < 0) {
            throw new IllegalArgumentException("offset must be >= 0, was " + offset);
        }
        if (targetContains != null && targetContains.isEmpty()) {
            targetContains = null;
        }
    }

    /** Same criteria, starting from the newest match (no offset). */
    public HistoryFilter(String targetContains, RiskLevel riskLevel, TargetType type,
                         Instant since, Instant until, int limit) {
        this(targetContains, riskLevel, type, since, until, limit, 0);
    }

    /** No criteria: the {@code limit} most recent scans. */
    public static HistoryFilter recent(int limit) {
        return new HistoryFilter(null, null, null, null, null, limit);
    }

    /** These criteria, one page at a time: {@code limit} rows after skipping {@code offset}. */
    public HistoryFilter page(int limit, int offset) {
        return new HistoryFilter(targetContains, riskLevel, type, since, until, limit, offset);
    }
}
