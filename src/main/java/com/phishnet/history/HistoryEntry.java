package com.phishnet.history;

import com.phishnet.cli.HistoryWriter.TargetType;
import com.phishnet.model.RiskLevel;

import java.time.Instant;
import java.util.List;

/**
 * One scan as read back from the {@link HistoryDatabase}.
 *
 * @param id            auto-increment row id
 * @param timestamp     when the scan was recorded
 * @param type          URL or EMAIL
 * @param target        the scanned URL, or the email's file path / upload label
 * @param domain        registrable domain (or IP host) for URL scans, sender domain for
 *                      email scans; {@code null} when there isn't one
 * @param subject       email subject line; {@code null} for URL scans
 * @param riskScore     0-100 score
 * @param riskLevel     LOW / MEDIUM / HIGH
 * @param reasons       the signals that fired, in the order the scorer reported them
 * @param domainAgeDays WHOIS domain age in whole days, or {@code null} when it isn't
 *                      known (lookup skipped or failed)
 */
public record HistoryEntry(long id, Instant timestamp, TargetType type, String target, String domain,
                           String subject, int riskScore, RiskLevel riskLevel, List<Reason> reasons,
                           Long domainAgeDays) {

    public HistoryEntry {
        reasons = reasons == null ? List.of() : List.copyOf(reasons);
    }

    /** One stored signal: its stable id plus the human-readable explanation. */
    public record Reason(String id, String description) {
    }
}
