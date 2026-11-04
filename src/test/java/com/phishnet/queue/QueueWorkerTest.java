package com.phishnet.queue;

import com.phishnet.analyzer.UrlAnalyzer;
import com.phishnet.batch.UrlScanner;
import com.phishnet.model.PhishNetConfig;
import com.phishnet.scoring.RiskScorer;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.BlockingDeque;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.LinkedBlockingDeque;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The worker loop and the job format, against an in-memory queue - no Redis involved. */
class QueueWorkerTest {

    private static final PhishNetConfig CONFIG = PhishNetConfig.defaultConfig();
    private static final UrlScanner SCANNER = new UrlScanner(new UrlAnalyzer(CONFIG), UrlScanner.SKIP_DOMAIN_AGE,
            new RiskScorer(CONFIG));
    private static final Duration FAST_POLL = Duration.ofMillis(20);

    /** A shared in-memory list standing in for Redis; each open() is one "connection". */
    private static final class MemoryQueue implements JobQueue {
        final BlockingDeque<String> jobs;

        MemoryQueue(BlockingDeque<String> jobs) {
            this.jobs = jobs;
        }

        @Override
        public long push(List<String> payloads) {
            jobs.addAll(payloads);
            return jobs.size();
        }

        @Override
        public Optional<String> take(Duration timeout) throws QueueException {
            try {
                return Optional.ofNullable(jobs.pollFirst(timeout.toMillis(), TimeUnit.MILLISECONDS));
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new QueueException("interrupted", e, false);
            }
        }

        @Override
        public long size() {
            return jobs.size();
        }

        @Override
        public void close() {
        }
    }

    /** Records listener events from any thread. */
    private static final class Events implements QueueWorker.Listener {
        final List<String> scanned = Collections.synchronizedList(new ArrayList<>());
        final List<String> invalid = Collections.synchronizedList(new ArrayList<>());
        final List<Duration> retries = Collections.synchronizedList(new ArrayList<>());
        final AtomicReference<QueueException> fatal = new AtomicReference<>();

        @Override
        public void scanned(ScanJob job, UrlScanner.Result result) {
            scanned.add(result.url() + "=" + result.score().level());
        }

        @Override
        public void invalidJob(String payload, String reason) {
            invalid.add(reason);
        }

        @Override
        public void jobFailed(ScanJob job, RuntimeException error) {
            invalid.add("failed:" + job.target());
        }

        @Override
        public void connectionLost(QueueException error, Duration retryIn, int attempt) {
            retries.add(retryIn);
        }

        @Override
        public void fatal(QueueException error) {
            fatal.set(error);
        }
    }

    private final BlockingDeque<String> jobs = new LinkedBlockingDeque<>();
    private final Events events = new Events();
    private final List<String> recorded = Collections.synchronizedList(new ArrayList<>());

    private QueueWorker worker(QueueWorker.QueueFactory factory, int threads, boolean retry,
                               List<Duration> slept) {
        return new QueueWorker(factory, SCANNER, result -> recorded.add(result.url()), events, threads, retry,
                true, FAST_POLL, slept::add);
    }

    private QueueWorker worker(int threads) {
        return worker(() -> new MemoryQueue(jobs), threads, false, new ArrayList<>());
    }

    @Test
    void workersDrainTheQueueScanningAndRecordingEachJobOnce() throws Exception {
        for (int i = 0; i < 200; i++) {
            jobs.add(ScanJob.create("http://site-" + i + ".tk/login", Instant.now()).toJson());
        }

        QueueWorker.Exit exit = worker(4).run();

        assertEquals(QueueWorker.Exit.STOPPED, exit);
        assertEquals(200, recorded.size());
        assertEquals(200, new java.util.HashSet<>(recorded).size(), "no job recorded twice");
        assertEquals(200, events.scanned.size());
        assertTrue(events.scanned.stream().allMatch(s -> s.endsWith("=MEDIUM") || s.endsWith("=HIGH")),
                "every .tk URL has the suspiciousTld signal");
        assertTrue(jobs.isEmpty());
    }

    @Test
    void bareUrlsAndInvalidJobsAreHandled() throws Exception {
        jobs.add("https://github.com/");
        jobs.add("{not json");
        jobs.add("{\"id\":\"1\"}");
        jobs.add("   ");

        worker(1).run();

        assertEquals(List.of("https://github.com/"), recorded);
        assertEquals(List.of("not valid JSON", "no \"target\" string", "empty job"), events.invalid);
    }

    @Test
    void unreachableQueueWithoutRetryStopsWithAFatalError() throws Exception {
        AtomicInteger opens = new AtomicInteger();
        QueueWorker worker = worker(() -> {
            opens.incrementAndGet();
            throw new QueueException("can't reach Redis at localhost:6379: Connection refused", null, false);
        }, 3, false, new ArrayList<>());

        assertEquals(QueueWorker.Exit.FATAL_ERROR, worker.run());
        assertTrue(events.fatal.get().getMessage().contains("Connection refused"));
        assertTrue(events.retries.isEmpty());
        assertTrue(opens.get() <= 3, "each thread tries once at most");
    }

    @Test
    void withRetryAWorkerReconnectsWithBackoffAndCarriesOn() throws Exception {
        jobs.add("http://a.tk/");
        jobs.add("http://b.tk/");
        AtomicInteger opens = new AtomicInteger();
        List<Duration> slept = Collections.synchronizedList(new ArrayList<>());
        QueueWorker worker = worker(() -> {
            if (opens.incrementAndGet() <= 3) {
                throw new QueueException("can't reach Redis", null, false);
            }
            return new MemoryQueue(jobs);
        }, 1, true, slept);

        assertEquals(QueueWorker.Exit.STOPPED, worker.run());
        assertEquals(List.of(Duration.ofSeconds(2), Duration.ofSeconds(4), Duration.ofSeconds(8)), slept);
        assertEquals(List.of("http://a.tk/", "http://b.tk/"), recorded);
        assertNull(events.fatal.get());
    }

    @Test
    void authenticationErrorsAreFatalEvenWithRetry() throws Exception {
        QueueWorker worker = worker(() -> {
            throw new QueueException("Redis refused the request: WRONGPASS invalid username-password pair", null, true);
        }, 2, true, new ArrayList<>());

        assertEquals(QueueWorker.Exit.FATAL_ERROR, worker.run());
        assertTrue(events.retries.isEmpty());
    }

    @Test
    void stopEndsIdleWorkersPromptly() throws Exception {
        QueueWorker worker = new QueueWorker(() -> new MemoryQueue(jobs), SCANNER, result -> { }, events, 3,
                false, false, FAST_POLL, null);
        AtomicReference<QueueWorker.Exit> exit = new AtomicReference<>();
        Thread runner = new Thread(() -> {
            try {
                exit.set(worker.run());
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        });
        runner.start();
        Thread.sleep(100);

        worker.stop();
        runner.join(5_000);

        assertFalse(runner.isAlive());
        assertEquals(QueueWorker.Exit.STOPPED, exit.get());
    }

    @Test
    void stopWakesAThreadWaitingToReconnect() throws Exception {
        QueueWorker worker = new QueueWorker(() -> {
            throw new QueueException("down", null, false);
        }, SCANNER, result -> { }, events, 1, true, false, FAST_POLL, null);
        Thread runner = new Thread(() -> {
            try {
                worker.run();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        });
        runner.start();
        while (events.retries.isEmpty()) {
            Thread.sleep(10); // now waiting out a 2 s backoff
        }

        long start = System.nanoTime();
        worker.stop();
        runner.join(5_000);

        assertFalse(runner.isAlive());
        assertTrue(System.nanoTime() - start < TimeUnit.SECONDS.toNanos(1), "didn't wait out the backoff");
    }

    @Test
    void checkConnectionReportsAnUnreachableQueueUpFront() {
        QueueWorker worker = worker(() -> {
            throw new QueueException("can't reach Redis", null, false);
        }, 1, false, new ArrayList<>());

        assertThrows(QueueException.class, worker::checkConnection);
    }

    // --- job format ------------------------------------------------------------------

    @Test
    void jobsRoundTripThroughJson() throws Exception {
        Instant now = Instant.parse("2026-11-04T09:00:00Z");
        ScanJob job = ScanJob.create("https://example.com/a?b=c", now);

        ScanJob parsed = ScanJob.parse(job.toJson());

        assertEquals(job, parsed);
        assertTrue(job.toJson().contains("\"target\":\"https://example.com/a?b=c\""));
        assertFalse(job.id().isBlank());
    }

    @Test
    void bareUrlPayloadIsAJob() throws Exception {
        ScanJob job = ScanJob.parse("  https://example.com/  ");

        assertEquals("https://example.com/", job.target());
        assertEquals("", job.id());
        assertNull(job.enqueuedAt());
    }

    @Test
    void invalidPayloadsAreRejected() {
        for (String payload : new String[] {"", "  ", "{", "{\"target\":42}", "{\"target\":\"  \"}",
                "x".repeat(ScanJob.MAX_TARGET_LENGTH + 1)}) {
            assertThrows(ScanJob.InvalidJobException.class, () -> ScanJob.parse(payload), payload);
        }
    }

    @Test
    void unparseableTimestampDoesNotInvalidateTheJob() throws Exception {
        ScanJob job = ScanJob.parse("{\"target\":\"https://example.com\",\"enqueuedAt\":\"yesterday\"}");

        assertEquals("https://example.com", job.target());
        assertNull(job.enqueuedAt());
    }

    @Test
    void redisSettingsNeverShowThePassword() {
        RedisSettings settings = new RedisSettings("redis.internal", 6380, "phishnet", "s3cret-redis", true, "jobs");

        assertFalse(settings.toString().contains("s3cret-redis"));
        assertTrue(settings.toString().contains("password=<redacted>"));
        assertEquals("Redis list \"jobs\" on redis.internal:6380 (TLS)", settings.describe());
        assertThrows(IllegalArgumentException.class, () -> new RedisSettings("h", 0, null, null, false, "q"));
        assertThrows(IllegalArgumentException.class, () -> new RedisSettings("h", 6379, null, null, false, " "));
    }

    @Test
    void scansAreSharedSafelyAcrossThreads() throws Exception {
        java.util.Set<String> threads = ConcurrentHashMap.newKeySet();
        for (int i = 0; i < 40; i++) {
            jobs.add("http://site-" + i + ".tk/");
        }
        QueueWorker worker = new QueueWorker(() -> new MemoryQueue(jobs), SCANNER, result -> {
            threads.add(Thread.currentThread().getName());
            recorded.add(result.url());
        }, events, 4, false, true, FAST_POLL, null);

        worker.run();

        assertEquals(40, recorded.size());
        assertTrue(threads.stream().allMatch(name -> name.startsWith("phishnet-queue-worker-")), threads.toString());
    }
}
