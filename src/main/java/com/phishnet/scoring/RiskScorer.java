package com.phishnet.scoring;

import com.phishnet.model.DomainAgeResult;
import com.phishnet.model.PhishNetConfig;
import com.phishnet.model.RiskLevel;
import com.phishnet.model.RiskScore;
import com.phishnet.model.Signal;
import com.phishnet.model.SignalCategory;

import java.util.ArrayList;
import java.util.List;

/**
 * Turns whatever signals the analyzers raised into a single 0-100 score and
 * a RiskLevel label. Weights and thresholds only live here - analyzers just
 * report what they found, they don't assign points.
 *
 * No parsing, no certificate checks, no email handling in this class on
 * purpose, so it can be tested with hand-built signal lists.
 */
public final class RiskScorer {

    public static final String DOMAIN_AGE_NEW = "domainAgeNew";
    public static final String DOMAIN_AGE_RECENT = "domainAgeRecent";
    public static final String DOMAIN_AGE_ESTABLISHED = "domainAgeEstablished";

    private final PhishNetConfig config;

    public RiskScorer(PhishNetConfig config) {
        this.config = config;
    }

    /**
     * Scores a combined list of signals from one or more analyzers. Weight
     * lookup is by signal id; if the same id shows up twice (e.g. two risky
     * links in one email) it counts twice. Clamps to 0-100, then maps to a
     * RiskLevel via the configured thresholds.
     */
    public RiskScore score(List<Signal> signals) {
        return score(signals, 0);
    }

    /**
     * Like {@link #score(List)}, plus a WHOIS domain age. Relative to the
     * configured day thresholds (boundaries: {@code age < domainAgeNewDays} is new,
     * {@code age <= domainAgeRecentDays} is recent):
     * <ul>
     *   <li>new: adds a {@code domainAgeNew} signal</li>
     *   <li>recent: adds a {@code domainAgeRecent} signal</li>
     *   <li>older: applies the {@code domainAgeEstablished} weight (normally a small
     *       negative number) without adding a signal - being old isn't a red flag,
     *       so it shouldn't be listed as one</li>
     * </ul>
     * An UNKNOWN or SKIPPED age contributes nothing at all.
     */
    public RiskScore score(List<Signal> signals, DomainAgeResult domainAge) {
        if (domainAge == null || !domainAge.isKnown()) {
            return score(signals);
        }
        var scoring = config.scoring();
        long age = domainAge.ageDays();
        String evidence = domainAge.domain() + " created " + domainAge.creationDate();

        List<Signal> combined = new ArrayList<>(signals);
        if (age < scoring.domainAgeNewDays()) {
            combined.add(new Signal(DOMAIN_AGE_NEW, SignalCategory.DOMAIN,
                    "Domain was registered very recently (" + domainAge.formatAge() + " ago)", evidence));
            return score(combined, 0);
        }
        if (age <= scoring.domainAgeRecentDays()) {
            combined.add(new Signal(DOMAIN_AGE_RECENT, SignalCategory.DOMAIN,
                    "Domain is relatively new (registered " + domainAge.formatAge() + " ago)", evidence));
            return score(combined, 0);
        }
        // Fallback 0, not the usual 10: a config written before this signal existed
        // must not start penalizing every well-established domain.
        return score(combined, scoring.weightOf(DOMAIN_AGE_ESTABLISHED, 0));
    }

    private RiskScore score(List<Signal> signals, int adjustment) {
        var scoring = config.scoring();

        int total = adjustment;
        for (Signal signal : signals) {
            total += scoring.weightOf(signal.id());
        }
        int clamped = Math.max(0, Math.min(100, total));

        RiskLevel level;
        if (clamped >= scoring.highThreshold()) {
            level = RiskLevel.HIGH;
        } else if (clamped >= scoring.mediumThreshold()) {
            level = RiskLevel.MEDIUM;
        } else {
            level = RiskLevel.LOW;
        }

        return new RiskScore(clamped, level, signals, recommendationFor(level));
    }

    private static String recommendationFor(RiskLevel level) {
        switch (level) {
            case HIGH:
                return "High risk of phishing. Do not click any links, enter credentials, or open attachments. "
                        + "Report and delete.";
            case MEDIUM:
                return "Some phishing indicators found. Proceed with caution: verify the sender/domain through "
                        + "a separate trusted channel before interacting.";
            case LOW:
            default:
                return "No strong phishing indicators found. Still verify anything requesting credentials "
                        + "or payment before acting on it.";
        }
    }
}
