package com.phishnet.model;

import java.time.LocalDate;

/**
 * The output of {@code DomainAgeChecker}: how long ago a domain was
 * registered, according to WHOIS - or why that couldn't be determined.
 *
 * Three states:
 * <ul>
 *   <li>{@link Status#KNOWN} - a creation date was found; {@link #ageDays()} is valid.</li>
 *   <li>{@link Status#UNKNOWN} - a lookup was attempted but failed (timeout, unreachable
 *       server, unparseable response, ...). Scoring stays neutral; the CLI shows
 *       "Domain Age: unknown".</li>
 *   <li>{@link Status#SKIPPED} - no lookup was attempted at all ({@code --no-whois}, an IP
 *       host, or a URL with no host). Nothing is scored and nothing is printed.</li>
 * </ul>
 * Contains no score - turning an age into points is the job of {@code RiskScorer}.
 */
public final class DomainAgeResult {

    public enum Status {
        KNOWN,
        UNKNOWN,
        SKIPPED
    }

    private static final DomainAgeResult SKIPPED = new DomainAgeResult(Status.SKIPPED, "", null, -1, "", "");

    private final Status status;
    private final String domain;
    private final LocalDate creationDate;
    private final long ageDays;
    private final String whoisServer;
    private final String reason;

    private DomainAgeResult(Status status, String domain, LocalDate creationDate, long ageDays,
                            String whoisServer, String reason) {
        this.status = status;
        this.domain = domain == null ? "" : domain;
        this.creationDate = creationDate;
        this.ageDays = ageDays;
        this.whoisServer = whoisServer == null ? "" : whoisServer;
        this.reason = reason == null ? "" : reason;
    }

    public static DomainAgeResult known(String domain, LocalDate creationDate, long ageDays, String whoisServer) {
        return new DomainAgeResult(Status.KNOWN, domain, creationDate, Math.max(0, ageDays), whoisServer, "");
    }

    public static DomainAgeResult unknown(String domain, String reason) {
        return new DomainAgeResult(Status.UNKNOWN, domain, null, -1, "", reason);
    }

    public static DomainAgeResult skipped() {
        return SKIPPED;
    }

    public Status status() {
        return status;
    }

    public boolean isKnown() {
        return status == Status.KNOWN;
    }

    public boolean isSkipped() {
        return status == Status.SKIPPED;
    }

    /** The registrable domain that was looked up, e.g. {@code "paypal.com"}. Empty when skipped. */
    public String domain() {
        return domain;
    }

    /** Registration date from WHOIS, or {@code null} unless {@link #isKnown()}. */
    public LocalDate creationDate() {
        return creationDate;
    }

    /** Whole days since registration, or {@code -1} unless {@link #isKnown()}. */
    public long ageDays() {
        return ageDays;
    }

    /** The WHOIS server that supplied the creation date. Empty unless {@link #isKnown()}. */
    public String whoisServer() {
        return whoisServer;
    }

    /** Why the age is unknown (e.g. "WHOIS lookup timed out"). Empty unless {@link Status#UNKNOWN}. */
    public String reason() {
        return reason;
    }

    /**
     * Human-readable age: "N days" under 60 days (so the 30-day scoring boundary
     * stays exact), "N months" under two years, "N years" beyond that.
     * "unknown" for UNKNOWN, empty for SKIPPED.
     */
    public String formatAge() {
        if (status == Status.UNKNOWN) {
            return "unknown";
        }
        if (status == Status.SKIPPED) {
            return "";
        }
        if (ageDays < 60) {
            return plural(ageDays, "day");
        }
        long years = (long) (ageDays / 365.25);
        if (years < 2) {
            return plural((long) (ageDays / 30.44), "month");
        }
        return plural(years, "year");
    }

    private static String plural(long n, String unit) {
        return n + " " + unit + (n == 1 ? "" : "s");
    }

    @Override
    public String toString() {
        return "DomainAgeResult{" + status + ", domain='" + domain + '\''
                + (isKnown() ? ", created=" + creationDate + ", ageDays=" + ageDays : "")
                + (reason.isEmpty() ? "" : ", reason='" + reason + '\'') + '}';
    }
}
