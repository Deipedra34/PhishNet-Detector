package com.phishnet.api;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.LongSupplier;

/**
 * Basic per-client rate limiting for {@code phishnet serve}: a token bucket per client
 * that holds up to {@code requestsPerMinute} tokens and refills continuously at that
 * rate. Each request takes a token; with none left the request is refused. So a client
 * can send a burst of up to the limit at once, then one more every {@code 60 / limit}
 * seconds, and an idle minute fills its bucket again.
 *
 * <p>Kept in memory and per process - basic abuse protection for a self-hosted tool, not
 * a distributed rate limiter. Thread-safe.
 */
public final class RateLimiter {

    /** The outcome of one request. */
    public record Decision(boolean allowed, long retryAfterSeconds) {
        static final Decision ALLOWED = new Decision(true, 0);
    }

    /** Buckets are pruned once this many clients are tracked, so memory stays bounded. */
    static final int MAX_TRACKED_CLIENTS = 10_000;

    private static final long NANOS_PER_MINUTE = 60_000_000_000L;
    private static final long ROUNDING_TOLERANCE_NANOS = 1_000_000L;

    private final int requestsPerMinute;
    private final LongSupplier nanoTime;
    private final Map<String, Bucket> buckets = new ConcurrentHashMap<>();

    /** @param requestsPerMinute how many requests each client may make per minute, at least 1 */
    public RateLimiter(int requestsPerMinute) {
        this(requestsPerMinute, System::nanoTime);
    }

    /** Same, with the clock swapped out (for tests). */
    RateLimiter(int requestsPerMinute, LongSupplier nanoTime) {
        if (requestsPerMinute < 1) {
            throw new IllegalArgumentException("requestsPerMinute must be at least 1, got " + requestsPerMinute);
        }
        this.requestsPerMinute = requestsPerMinute;
        this.nanoTime = nanoTime;
    }

    public int requestsPerMinute() {
        return requestsPerMinute;
    }

    /** Takes a token for {@code client} (e.g. its IP address) if one is available. */
    public Decision tryAcquire(String client) {
        long now = nanoTime.getAsLong();
        if (buckets.size() >= MAX_TRACKED_CLIENTS) {
            prune(now);
        }
        return buckets.computeIfAbsent(client, c -> new Bucket(requestsPerMinute, now)).tryAcquire(now);
    }

    /** Clients currently tracked (for tests). */
    int trackedClients() {
        return buckets.size();
    }

    /** Drops buckets that have refilled completely - forgetting them changes nothing. */
    private void prune(long now) {
        buckets.values().removeIf(bucket -> bucket.isFull(now));
    }

    private final class Bucket {
        private double tokens;
        private long lastRefill;

        Bucket(double tokens, long now) {
            this.tokens = tokens;
            this.lastRefill = now;
        }

        synchronized Decision tryAcquire(long now) {
            refill(now);
            if (tokens >= 1) {
                tokens -= 1;
                return Decision.ALLOWED;
            }
            double nanosUntilToken = (1 - tokens) * NANOS_PER_MINUTE / requestsPerMinute;
            // Rounded up to whole seconds, less 1 ms so floating-point drift can't turn an exact 10 s into 11.
            long seconds = (long) Math.ceil((nanosUntilToken - ROUNDING_TOLERANCE_NANOS) / 1_000_000_000d);
            return new Decision(false, Math.max(1, seconds));
        }

        synchronized boolean isFull(long now) {
            refill(now);
            return tokens >= requestsPerMinute;
        }

        private void refill(long now) {
            long elapsed = now - lastRefill;
            if (elapsed > 0) {
                tokens = Math.min(requestsPerMinute, tokens + (double) elapsed * requestsPerMinute / NANOS_PER_MINUTE);
                lastRefill = now;
            }
        }
    }
}
