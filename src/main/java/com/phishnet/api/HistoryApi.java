package com.phishnet.api;

import com.phishnet.history.HistoryDatabase;
import com.phishnet.history.HistoryEntry;
import com.phishnet.history.HistoryFilter;
import io.javalin.http.BadRequestResponse;
import io.javalin.http.Context;

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

    /** Page size of {@code GET /api/history} when no {@code limit} is given. */
    static final int DEFAULT_LIMIT = 20;
    /** Largest page {@code GET /api/history} returns. */
    static final int MAX_LIMIT = 200;

    private final HistoryDatabase database;

    HistoryApi(HistoryDatabase database) {
        this.database = database;
    }

    /**
     * {@code GET /api/history?limit=&offset=}: one page of scans, newest first, plus
     * the total number of scans, so a client can page through them.
     */
    Map<String, Object> list(Context ctx) throws SQLException {
        int limit = intParam(ctx, "limit", DEFAULT_LIMIT, 1, MAX_LIMIT);
        int offset = intParam(ctx, "offset", 0, 0, Integer.MAX_VALUE);
        HistoryFilter criteria = HistoryFilter.recent(0);

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("total", database.count(criteria));
        body.put("limit", limit);
        body.put("offset", offset);
        body.put("scans", toJson(database.search(criteria.page(limit, offset))));
        return body;
    }

    /** An optional whole-number query parameter within {@code [min, max]}; a 400 otherwise. */
    static int intParam(Context ctx, String name, int defaultValue, int min, int max) {
        String raw = ctx.queryParam(name);
        if (raw == null || raw.isBlank()) {
            return defaultValue;
        }
        int value;
        try {
            value = Integer.parseInt(raw.trim());
        } catch (NumberFormatException e) {
            throw new BadRequestResponse("Query parameter '" + name + "' must be a whole number");
        }
        if (value < min || value > max) {
            throw new BadRequestResponse("Query parameter '" + name + "' must be "
                    + (max == Integer.MAX_VALUE ? min + " or more" : "between " + min + " and " + max));
        }
        return value;
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
