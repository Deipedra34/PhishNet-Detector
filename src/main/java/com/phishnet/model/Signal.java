package com.phishnet.model;

import java.util.Objects;

/**
 * One risk indicator raised by an analyzer (URL, SSL, or email).
 *
 * id() has to match a key in the scoring config's weight table so RiskScorer
 * knows how many points to add. Analyzers just report what they saw, they
 * don't decide point values themselves.
 */
public final class Signal {

    private final String id;
    private final SignalCategory category;
    private final String description;
    private final String evidence;

    public Signal(String id, SignalCategory category, String description, String evidence) {
        this.id = Objects.requireNonNull(id, "id");
        this.category = Objects.requireNonNull(category, "category");
        this.description = Objects.requireNonNull(description, "description");
        this.evidence = evidence == null ? "" : evidence;
    }

    public Signal(String id, SignalCategory category, String description) {
        this(id, category, description, null);
    }

    /** Stable machine-readable key, e.g. {@code "typosquatting"}. Matches a scoring weight key. */
    public String id() {
        return id;
    }

    public SignalCategory category() {
        return category;
    }

    /** Human-readable explanation of why this signal fired. */
    public String description() {
        return description;
    }

    /** Optional extra detail (e.g. the matched brand, the offending keyword). */
    public String evidence() {
        return evidence;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Signal)) return false;
        Signal signal = (Signal) o;
        return id.equals(signal.id) && category == signal.category
                && description.equals(signal.description) && evidence.equals(signal.evidence);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, category, description, evidence);
    }

    @Override
    public String toString() {
        return "Signal{" + "id='" + id + '\'' + ", category=" + category
                + ", description='" + description + '\''
                + (evidence.isEmpty() ? "" : ", evidence='" + evidence + '\'') + '}';
    }
}
