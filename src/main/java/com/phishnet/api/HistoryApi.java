package com.phishnet.api;

import com.phishnet.cli.HistoryWriter.TargetType;
import com.phishnet.history.HistoryDatabase;
import com.phishnet.history.HistoryEntry;
import com.phishnet.history.HistoryFilter;
import com.phishnet.model.RiskLevel;
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
     * {@code GET /api/history?limit=&offset=&target=&risk=&type=}: one page of the
     * matching scans, newest first, plus how many match in total, so a client can
     * page through them. The filters are those of {@code phishnet history search}:
     * {@code target} is a case-insensitive substring of the URL, domain, email file
     * name, or subject; {@code risk} and {@code type} are exact (case-insensitive).
     */
    Map<String, Object> list(Context ctx) throws SQLException {
        int limit = intParam(ctx, "limit", DEFAULT_LIMIT, 1, MAX_LIMIT);
        int offset = intParam(ctx, "offset", 0, 0, Integer.MAX_VALUE);
        String target = ctx.queryParam("target");
        RiskLevel risk = enumParam(ctx, "risk", RiskLevel.class);
        TargetType type = enumParam(ctx, "type", TargetType.class);
        HistoryFilter criteria = new HistoryFilter(target == null ? null : target.trim(), risk, type,
                null, null, 0);

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

    /** An optional enum query parameter, by constant name in any case; a 400 for anything else. */
    static <E extends Enum<E>> E enumParam(Context ctx, String name, Class<E> type) {
        String raw = ctx.queryParam(name);
        if (raw == null || raw.isBlank()) {
            return null;
        }
        String wanted = raw.trim();
        List<String> names = new ArrayList<>();
        for (E constant : type.getEnumConstants()) {
            if (constant.name().equalsIgnoreCase(wanted)) {
                return constant;
            }
            names.add(constant.name());
        }
        throw new BadRequestResponse("Query parameter '" + name + "' must be one of " + String.join(", ", names));
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
