package com.phishnet.batch;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.IntStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ParallelScannerTest {

    private static List<Integer> numbers(int count) {
        return IntStream.range(0, count).boxed().toList();
    }

    @Test
    void everyJobRunsExactlyOnceAndResultsComeBackInInputOrder() throws Exception {
        List<Integer> jobs = numbers(500);
        Set<Integer> seen = ConcurrentHashMap.newKeySet();
        AtomicInteger calls = new AtomicInteger();

        List<String> results = new ParallelScanner(8).run(jobs, n -> {
            calls.incrementAndGet();
            assertTrue(seen.add(n), "job " + n + " ran twice");
            // Uneven work makes jobs finish out of order.
            if (n % 7 == 0) {
                try {
                    Thread.sleep(1);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
            return "r" + n;
        }, (index, result) -> { }, (done, total) -> { });

        assertEquals(500, calls.get());
        assertEquals(jobs.stream().map(n -> "r" + n).toList(), results);
    }

    @Test
    void inOrderCallbackSeesInputOrderWhileProgressCountsEveryCompletion() throws Exception {
        List<Integer> jobs = numbers(200);
        List<Integer> orderSeen = new ArrayList<>();
        List<Integer> progressSeen = new ArrayList<>();
        List<String> callbackThreads = Collections.synchronizedList(new ArrayList<>());

        new ParallelScanner(6).run(jobs,
                n -> {
                    try {
                        Thread.sleep((200 - n) % 5); // later jobs tend to finish first
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    }
                    return n;
                },
                (index, result) -> {
                    assertEquals(index, (int) result);
                    orderSeen.add(index);
                    callbackThreads.add(Thread.currentThread().getName());
                },
                (done, total) -> {
                    assertEquals(200, total);
                    progressSeen.add(done);
                    callbackThreads.add(Thread.currentThread().getName());
                });

        assertEquals(jobs, orderSeen);
        assertEquals(IntStream.rangeClosed(1, 200).boxed().toList(), progressSeen);
        assertEquals(Set.of(Thread.currentThread().getName()), Set.copyOf(callbackThreads),
                "callbacks run on the calling thread only, never concurrently");
    }

    @Test
    void jobsReallyRunInParallel() throws Exception {
        int threads = 4;
        CountDownLatch allRunning = new CountDownLatch(threads);

        List<Boolean> results = new ParallelScanner(threads).run(numbers(threads), n -> {
            allRunning.countDown();
            try {
                // Only returns true if all four jobs were in flight at the same time.
                return allRunning.await(10, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return false;
            }
        }, (index, result) -> { }, (done, total) -> { });

        assertEquals(List.of(true, true, true, true), results);
    }

    @Test
    void oneThreadRunsJobsOneAtATimeInOrder() throws Exception {
        AtomicInteger inFlight = new AtomicInteger();
        AtomicInteger maxInFlight = new AtomicInteger();
        List<Integer> started = Collections.synchronizedList(new ArrayList<>());

        new ParallelScanner(1).run(numbers(50), n -> {
            maxInFlight.accumulateAndGet(inFlight.incrementAndGet(), Math::max);
            started.add(n);
            inFlight.decrementAndGet();
            return n;
        }, (index, result) -> { }, (done, total) -> { });

        assertEquals(1, maxInFlight.get());
        assertEquals(numbers(50), started);
    }

    @Test
    void failingJobStopsTheRunAndRethrows() {
        IllegalStateException boom = new IllegalStateException("boom");
        AtomicInteger recorded = new AtomicInteger();

        IllegalStateException thrown = assertThrows(IllegalStateException.class,
                () -> new ParallelScanner(4).run(numbers(100), n -> {
                    if (n == 10) {
                        throw boom;
                    }
                    return n;
                }, (index, result) -> recorded.incrementAndGet(), (done, total) -> { }));

        assertSame(boom, thrown);
        assertTrue(recorded.get() <= 10, "nothing after the failed job is handed on");
    }

    @Test
    void emptyInputAndMoreThreadsThanJobs() throws Exception {
        assertEquals(List.of(), new ParallelScanner(4).run(List.<Integer>of(), n -> n,
                (index, result) -> { }, (done, total) -> { }));
        assertEquals(List.of(0, 1), new ParallelScanner(16).run(numbers(2), n -> n,
                (index, result) -> { }, (done, total) -> { }));
    }

    @Test
    void threadCountIsValidated() {
        assertThrows(IllegalArgumentException.class, () -> new ParallelScanner(0));
        assertThrows(IllegalArgumentException.class, () -> new ParallelScanner(ParallelScanner.MAX_THREADS + 1));
        assertTrue(ParallelScanner.defaultThreads() >= 1);
        assertEquals(Math.min(ParallelScanner.MAX_THREADS, Runtime.getRuntime().availableProcessors()),
                ParallelScanner.defaultThreads());
    }
}
