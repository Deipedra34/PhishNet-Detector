package com.phishnet.history;

import com.phishnet.cli.HistoryWriter.TargetType;
import com.phishnet.model.RiskLevel;

import java.time.Instant;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

/**
 * Aggregate figures over the whole {@link HistoryDatabase}.
 *
 * @param total               number of recorded scans
 * @param byRiskLevel         scan count per risk level (every level present, zero if unused)
 * @param byType              scan count per target type (every type present, zero if unused)
 * @param firstScan           oldest timestamp, or {@code null} when there are no scans
 * @param lastScan            newest timestamp, or {@code null} when there are no scans
 * @param topFlaggedDomains   domains with the most MEDIUM/HIGH scans, most frequent first
 */
public record HistoryStats(long total, Map<RiskLevel, Long> byRiskLevel, Map<TargetType, Long> byType,
                           Instant firstScan, Instant lastScan, List<DomainCount> topFlaggedDomains) {

    public HistoryStats {
        byRiskLevel = Map.copyOf(withZeros(byRiskLevel, RiskLevel.class));
        byType = Map.copyOf(withZeros(byType, TargetType.class));
        topFlaggedDomains = topFlaggedDomains == null ? List.of() : List.copyOf(topFlaggedDomains);
    }

    /** Stats for a history with no scans in it. */
    public static HistoryStats empty() {
        return new HistoryStats(0, Map.of(), Map.of(), null, null, List.of());
    }

    /** How many MEDIUM/HIGH scans a domain has. */
    public record DomainCount(String domain, long count) {
    }

    private static <E extends Enum<E>> Map<E, Long> withZeros(Map<E, Long> counts, Class<E> type) {
        Map<E, Long> filled = new EnumMap<>(type);
        for (E value : type.getEnumConstants()) {
            filled.put(value, counts == null ? 0L : counts.getOrDefault(value, 0L));
        }
        return filled;
    }
}
