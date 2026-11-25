package com.phishnet.model;

import com.phishnet.i18n.Messages;
import com.phishnet.i18n.Text;

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
    /** The description as a message, or null for a signal built from plain text. */
    private final Text text;

    public Signal(String id, SignalCategory category, String description, String evidence) {
        this(id, category, description, evidence, null);
    }

    /**
     * A signal whose description can be shown in any supported language;
     * {@link #description()} is its English text.
     */
    public Signal(String id, SignalCategory category, Text description, String evidence) {
        this(id, category, Objects.requireNonNull(description, "description").english(), evidence, description);
    }

    private Signal(String id, SignalCategory category, String description, String evidence, Text text) {
        this.id = Objects.requireNonNull(id, "id");
        this.category = Objects.requireNonNull(category, "category");
        this.description = Objects.requireNonNull(description, "description");
        this.evidence = evidence == null ? "" : evidence;
        this.text = text;
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

    /** {@link #description()} in {@code messages}' language (as-is for a signal built from plain text). */
    public String description(Messages messages) {
        return text == null ? description : text.in(messages);
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
