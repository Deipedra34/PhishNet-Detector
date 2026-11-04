package com.phishnet.batch;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;

/**
 * Runs a list of scan jobs on a fixed pool of worker threads.
 *
 * <p>A feeder thread puts the jobs on a bounded {@link BlockingQueue}; each worker
 * takes jobs off it and scans them; finished results come back to the thread that
 * called {@link #run}. That calling thread does everything with side effects, one
 * result at a time - so callbacks never run concurrently and need no locking:
 * <ul>
 *   <li>{@code progress} is called once per finished job, in completion order
 *       ({@code completed} counts 1, 2, 3, ... regardless of which job finished);</li>
 *   <li>{@code inOrder} is called for job 0, 1, 2, ... in input order, each as soon as
 *       it and every job before it have finished. Writing history from there keeps
 *       the history files in input order, just like a sequential scan.</li>
 * </ul>
 *
 * <p>If a job throws, the remaining work is cancelled and the exception is rethrown
 * from {@link #run} - the same outcome as the exception in a sequential loop.
 */
public final class ParallelScanner {

    /** Upper bound for {@code --threads}; far more than WHOIS-bound scans ever benefit from. */
    public static final int MAX_THREADS = 256;

    /** Receives results in input order. */
    @FunctionalInterface
    public interface InOrderConsumer<R> {
        void accept(int index, R result);
    }

    /** Hears about each finished job, in completion order. */
    @FunctionalInterface
    public interface ProgressCallback {
        void completed(int completed, int total);
    }

    private static final AtomicInteger POOL_IDS = new AtomicInteger();

    private final int threads;

    /** @param threads worker threads, 1 to {@link #MAX_THREADS} */
    public ParallelScanner(int threads) {
        if (threads < 1 || threads > MAX_THREADS) {
            throw new IllegalArgumentException("threads must be 1-" + MAX_THREADS + ", got " + threads);
        }
        this.threads = threads;
    }

    /** One per available CPU core - the default for {@code --threads}. */
    public static int defaultThreads() {
        return Math.min(MAX_THREADS, Math.max(1, Runtime.getRuntime().availableProcessors()));
    }

    public int threads() {
        return threads;
    }

    private record Job<J>(int index, J job) {
    }

    private record Done<R>(int index, R result, Throwable error) {
    }

    /**
     * Scans every job and returns the results in input order.
     *
     * @throws InterruptedException if the calling thread is interrupted while waiting
     */
    public <J, R> List<R> run(List<J> jobs, Function<? super J, ? extends R> scan,
                              InOrderConsumer<? super R> inOrder, ProgressCallback progress)
            throws InterruptedException {
        int total = jobs.size();
        if (total == 0) {
            return List.of();
        }
        int workers = Math.min(threads, total);
        // Bounded: the feeder stays only a little ahead of the workers instead of
        // queueing every job up front.
        BlockingQueue<Job<J>> queue = new ArrayBlockingQueue<>(workers * 2);
        BlockingQueue<Done<R>> finished = new LinkedBlockingQueue<>();
        Job<J> stop = new Job<>(-1, null);

        int poolId = POOL_IDS.incrementAndGet();
        ExecutorService pool = Executors.newFixedThreadPool(workers, daemonThreads("phishnet-scan-" + poolId + "-"));
        for (int w = 0; w < workers; w++) {
            pool.execute(() -> {
                try {
                    for (Job<J> job = queue.take(); job != stop; job = queue.take()) {
                        Done<R> done;
                        try {
                            done = new Done<>(job.index(), scan.apply(job.job()), null);
                        } catch (Throwable t) {
                            done = new Done<>(job.index(), null, t);
                        }
                        finished.add(done);
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt(); // cancelled
                }
            });
        }
        Thread feeder = daemonThreads("phishnet-scan-" + poolId + "-feeder").newThread(() -> {
            try {
                for (int i = 0; i < total; i++) {
                    queue.put(new Job<>(i, jobs.get(i)));
                }
                for (int w = 0; w < workers; w++) {
                    queue.put(stop);
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt(); // cancelled
            }
        });
        feeder.start();

        Object[] results = new Object[total];
        boolean[] ready = new boolean[total];
        int nextInOrder = 0;
        try {
            for (int completed = 1; completed <= total; completed++) {
                Done<R> done = finished.take();
                if (done.error() != null) {
                    throw rethrow(done.error());
                }
                results[done.index()] = done.result();
                ready[done.index()] = true;
                progress.completed(completed, total);
                while (nextInOrder < total && ready[nextInOrder]) {
                    @SuppressWarnings("unchecked")
                    R result = (R) results[nextInOrder];
                    inOrder.accept(nextInOrder, result);
                    nextInOrder++;
                }
            }
        } finally {
            feeder.interrupt();
            pool.shutdownNow();
        }

        List<R> ordered = new ArrayList<>(total);
        for (Object result : results) {
            @SuppressWarnings("unchecked")
            R typed = (R) result;
            ordered.add(typed);
        }
        return ordered;
    }

    private static RuntimeException rethrow(Throwable error) {
        if (error instanceof RuntimeException runtime) {
            return runtime;
        }
        if (error instanceof Error fatal) {
            throw fatal;
        }
        return new IllegalStateException("scan job failed: " + error, error);
    }

    private static ThreadFactory daemonThreads(String prefix) {
        AtomicInteger count = new AtomicInteger();
        return runnable -> {
            Thread thread = new Thread(runnable, prefix + count.incrementAndGet());
            // A worker stuck on a slow WHOIS server must not keep the JVM alive after the batch ends.
            thread.setDaemon(true);
            return thread;
        };
    }

    @Override
    public String toString() {
        return "ParallelScanner[threads=" + threads + "]";
    }
}
