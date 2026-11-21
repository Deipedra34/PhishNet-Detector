package com.phishnet.api;

import org.junit.jupiter.api.Test;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The token bucket, on a fake clock - no waiting. */
class RateLimiterTest {

    private final AtomicLong now = new AtomicLong(1_000_000_000L);

    private RateLimiter limiter(int perMinute) {
        return new RateLimiter(perMinute, now::get);
    }

    private void advanceSeconds(double seconds) {
        now.addAndGet((long) (seconds * TimeUnit.SECONDS.toNanos(1)));
    }

    @Test
    void allowsTheLimitThenRefuses() {
        RateLimiter limiter = limiter(5);

        for (int i = 0; i < 5; i++) {
            assertTrue(limiter.tryAcquire("1.2.3.4").allowed(), "request " + (i + 1));
        }
        RateLimiter.Decision refused = limiter.tryAcquire("1.2.3.4");

        assertFalse(refused.allowed());
        assertEquals(12, refused.retryAfterSeconds(), "one token every 60 / 5 = 12 seconds");
    }

    @Test
    void resetsAfterTheWindow() {
        RateLimiter limiter = limiter(3);
        for (int i = 0; i < 3; i++) {
            limiter.tryAcquire("client");
        }
        assertFalse(limiter.tryAcquire("client").allowed());

        advanceSeconds(60);

        for (int i = 0; i < 3; i++) {
            assertTrue(limiter.tryAcquire("client").allowed(), "a full minute later the whole allowance is back");
        }
        assertFalse(limiter.tryAcquire("client").allowed(), "but not more than the limit");
    }

    @Test
    void refillsGraduallyWithinTheWindow() {
        RateLimiter limiter = limiter(60); // one token per second
        for (int i = 0; i < 60; i++) {
            limiter.tryAcquire("client");
        }
        assertFalse(limiter.tryAcquire("client").allowed());
        assertEquals(1, limiter.tryAcquire("client").retryAfterSeconds());

        advanceSeconds(1);
        assertTrue(limiter.tryAcquire("client").allowed());
        assertFalse(limiter.tryAcquire("client").allowed());

        advanceSeconds(10);
        for (int i = 0; i < 10; i++) {
            assertTrue(limiter.tryAcquire("client").allowed());
        }
        assertFalse(limiter.tryAcquire("client").allowed());
    }

    @Test
    void retryAfterCountsDownAsTimePasses() {
        RateLimiter limiter = limiter(2); // one token every 30 seconds
        limiter.tryAcquire("c");
        limiter.tryAcquire("c");

        assertEquals(30, limiter.tryAcquire("c").retryAfterSeconds());
        advanceSeconds(20);
        assertEquals(10, limiter.tryAcquire("c").retryAfterSeconds());
        advanceSeconds(9.5);
        assertEquals(1, limiter.tryAcquire("c").retryAfterSeconds(), "never less than 1");
    }

    @Test
    void clientsHaveSeparateAllowances() {
        RateLimiter limiter = limiter(1);

        assertTrue(limiter.tryAcquire("10.0.0.1").allowed());
        assertFalse(limiter.tryAcquire("10.0.0.1").allowed());
        assertTrue(limiter.tryAcquire("10.0.0.2").allowed(), "another client isn't affected");
    }

    @Test
    void idleClientsArePrunedSoMemoryStaysBounded() {
        RateLimiter limiter = limiter(10);
        for (int i = 0; i < RateLimiter.MAX_TRACKED_CLIENTS; i++) {
            limiter.tryAcquire("client-" + i);
        }
        assertEquals(RateLimiter.MAX_TRACKED_CLIENTS, limiter.trackedClients());

        advanceSeconds(60); // every bucket refills completely
        limiter.tryAcquire("newcomer");

        assertEquals(1, limiter.trackedClients(), "full buckets were forgotten");
    }

    @Test
    void concurrentRequestsNeverExceedTheLimit() throws Exception {
        RateLimiter limiter = limiter(100);
        AtomicLong allowed = new AtomicLong();
        Thread[] threads = new Thread[8];
        for (int t = 0; t < threads.length; t++) {
            threads[t] = new Thread(() -> {
                for (int i = 0; i < 50; i++) {
                    if (limiter.tryAcquire("shared").allowed()) {
                        allowed.incrementAndGet();
                    }
                }
            });
            threads[t].start();
        }
        for (Thread thread : threads) {
            thread.join();
        }

        assertEquals(100, allowed.get());
    }

    @Test
    void limitMustBePositive() {
        assertThrows(IllegalArgumentException.class, () -> new RateLimiter(0));
        assertEquals(60, new RateLimiter(60).requestsPerMinute());
    }

    @Test
    void configSectionSetsTheLimitWithASensibleDefault() {
        assertEquals(60, com.phishnet.util.ConfigLoader.loadDefault().api().rateLimitPerMinute());
        assertEquals(60, com.phishnet.util.ConfigLoader.load(stream("brands: []\n")).api().rateLimitPerMinute(),
                "no api section: the default");
        assertEquals(15, com.phishnet.util.ConfigLoader.load(stream("api:\n  rateLimitPerMinute: 15\n"))
                .api().rateLimitPerMinute());
        assertThrows(IllegalArgumentException.class,
                () -> com.phishnet.util.ConfigLoader.load(stream("api:\n  rateLimitPerMinute: -1\n")));
    }

    private static java.io.InputStream stream(String yaml) {
        return new java.io.ByteArrayInputStream(yaml.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }
}
