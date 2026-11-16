package com.phishnet.api;

import com.phishnet.history.HistoryDatabase;
import com.phishnet.history.HistoryEntry;
import com.phishnet.history.HistoryFilter;

import java.sql.SQLException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The read-only scan history endpoints the web dashboard uses. A thin JSON layer
 * over {@link HistoryDatabase}: every query goes through the same methods
 * {@code phishnet history} uses, so the API and the CLI always agree.
 */
final class HistoryApi {

    /** How many scans {@code GET /api/history} returns. */
    static final int DEFAULT_LIMIT = 20;

    private final HistoryDatabase database;

    HistoryApi(HistoryDatabase database) {
        this.database = database;
    }

    /** {@code GET /api/history}: the most recent scans, newest first. */
    Map<String, Object> list() throws SQLException {
        List<HistoryEntry> entries = database.search(HistoryFilter.recent(DEFAULT_LIMIT));
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("scans", toJson(entries));
        return body;
    }

    static List<Map<String, Object>> toJson(List<HistoryEntry> entries) {
        List<Map<String, Object>> scans = new ArrayList<>();
        for (HistoryEntry entry : entries) {
            scans.add(toJson(entry));
        }
        return scans;
    }

    /** One stored scan. Field names match the database columns, in camelCase. */
    static Map<String, Object> toJson(HistoryEntry entry) {
        Map<String, Object> scan = new LinkedHashMap<>();
        scan.put("id", entry.id());
        scan.put("timestamp", entry.timestamp().toString());
        scan.put("type", entry.type().name());
        scan.put("target", entry.target());
        scan.put("domain", entry.domain());
        scan.put("subject", entry.subject());
        scan.put("riskScore", entry.riskScore());
        scan.put("riskLevel", entry.riskLevel().name());
        List<Map<String, Object>> reasons = new ArrayList<>();
        for (HistoryEntry.Reason reason : entry.reasons()) {
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("id", reason.id());
            item.put("description", reason.description());
            reasons.add(item);
        }
        scan.put("reasons", reasons);
        scan.put("domainAgeDays", entry.domainAgeDays());
        return scan;
    }
}
