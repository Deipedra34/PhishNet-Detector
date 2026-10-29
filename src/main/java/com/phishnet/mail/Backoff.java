package com.phishnet.mail;

import java.time.Duration;

/**
 * Exponential reconnect delays: {@code initial}, then doubling up to {@code max}
 * (2s, 4s, 8s, ... 5 min by default), back to {@code initial} after a successful
 * connection. Not thread-safe; used only by the monitor loop.
 */
public final class Backoff {

    public static final Duration DEFAULT_INITIAL = Duration.ofSeconds(2);
    public static final Duration DEFAULT_MAX = Duration.ofMinutes(5);

    private final Duration initial;
    private final Duration max;
    private Duration next;
    private int attempt;

    public Backoff() {
        this(DEFAULT_INITIAL, DEFAULT_MAX);
    }

    public Backoff(Duration initial, Duration max) {
        if (initial.isNegative() || initial.isZero() || max.compareTo(initial) < 0) {
            throw new IllegalArgumentException("need 0 < initial <= max");
        }
        this.initial = initial;
        this.max = max;
        reset();
    }

    /** The delay before the next attempt; each call doubles the following one, up to the maximum. */
    public Duration nextDelay() {
        Duration delay = next;
        attempt++;
        next = next.multipliedBy(2).compareTo(max) > 0 ? max : next.multipliedBy(2);
        return delay;
    }

    /** Failed attempts since the last reset (1 after the first {@link #nextDelay()}). */
    public int attempts() {
        return attempt;
    }

    public void reset() {
        next = initial;
        attempt = 0;
    }
}
