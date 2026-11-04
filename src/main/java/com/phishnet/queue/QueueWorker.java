package com.phishnet.queue;

import com.phishnet.batch.UrlScanner;
import com.phishnet.mail.Backoff;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;

/**
 * A long-running worker for the distributed mode: {@code threads} threads, each with
 * its own queue connection, take jobs ({@link JobQueue#take}), scan them with the same
 * {@link UrlScanner} pipeline as {@code --batch}, and record the results. Run as many
 * workers, on as many machines, as you like against one queue - each job goes to one
 * of them.
 *
 * <p>Connection problems: with {@code retry} on, a thread that can't reach the queue
 * waits with exponential backoff (2 s doubling up to 1 min) and reconnects; with it
 * off, the first connection failure stops the whole worker with an error. Errors that
 * reconnecting can't fix (a wrong password) always stop it.
 */
public final class QueueWorker {

    /** How a {@link #run()} ended. */
    public enum Exit {
        /** Stopped by {@link #stop()}, or the queue was empty with {@code exitWhenEmpty}. */
        STOPPED,
        /** The queue couldn't be used, reported through {@link Listener#fatal}. */
        FATAL_ERROR
    }

    /** Progress callbacks; called from the worker threads, so implementations must be thread-safe. */
    public interface Listener {
        void scanned(ScanJob job, UrlScanner.Result result);

        void invalidJob(String payload, String reason);

        void jobFailed(ScanJob job, RuntimeException error);

        void connectionLost(QueueException error, Duration retryIn, int attempt);

        void fatal(QueueException error);
    }

    /** Opens a queue connection; each worker thread gets its own. */
    @FunctionalInterface
    public interface QueueFactory {
        JobQueue open() throws QueueException;
    }

    /** Records a scan result (scan history); called from the worker threads. */
    @FunctionalInterface
    public interface Recorder {
        void record(UrlScanner.Result result);
    }

    /** Thread.sleep, swappable so tests don't actually wait. */
    @FunctionalInterface
    public interface Sleeper {
        void sleep(Duration duration) throws InterruptedException;
    }

    /**
     * How long one BRPOP waits - also how quickly an idle worker notices {@link #stop()} or,
     * with {@code exitWhenEmpty}, an empty queue. One blocking call per idle thread per
     * second is negligible load for Redis.
     */
    public static final Duration DEFAULT_POLL_TIMEOUT = Duration.ofSeconds(1);

    static final Duration RETRY_INITIAL = Duration.ofSeconds(2);
    static final Duration RETRY_MAX = Duration.ofMinutes(1);

    private final QueueFactory queues;
    private final UrlScanner scanner;
    private final Recorder recorder;
    private final Listener listener;
    private final int threads;
    private final boolean retry;
    private final boolean exitWhenEmpty;
    private final Duration pollTimeout;
    private final Sleeper sleeper;

    private final List<Thread> workers = new ArrayList<>();
    private final AtomicReference<QueueException> fatalError = new AtomicReference<>();
    /** Wakes threads waiting to reconnect when the worker stops. */
    private final Object stopSignal = new Object();
    private volatile boolean running;

    public QueueWorker(QueueFactory queues, UrlScanner scanner, Recorder recorder, Listener listener, int threads,
                       boolean retry, boolean exitWhenEmpty) {
        this(queues, scanner, recorder, listener, threads, retry, exitWhenEmpty, DEFAULT_POLL_TIMEOUT, null);
    }

    QueueWorker(QueueFactory queues, UrlScanner scanner, Recorder recorder, Listener listener, int threads,
                boolean retry, boolean exitWhenEmpty, Duration pollTimeout, Sleeper sleeper) {
        if (threads < 1) {
            throw new IllegalArgumentException("threads must be at least 1");
        }
        this.queues = Objects.requireNonNull(queues);
        this.scanner = Objects.requireNonNull(scanner);
        this.recorder = Objects.requireNonNull(recorder);
        this.listener = Objects.requireNonNull(listener);
        this.threads = threads;
        this.retry = retry;
        this.exitWhenEmpty = exitWhenEmpty;
        this.pollTimeout = Objects.requireNonNull(pollTimeout);
        this.sleeper = sleeper != null ? sleeper : this::waitUnlessStopped;
    }

    /**
     * The default {@link Sleeper}: waits on a monitor that {@link #stop()} signals, rather
     * than relying on thread interrupts - an interrupt landing during a history write
     * would close its file channel and lose that row.
     */
    private void waitUnlessStopped(Duration duration) throws InterruptedException {
        synchronized (stopSignal) {
            if (running) {
                stopSignal.wait(Math.max(1, duration.toMillis()));
            }
        }
    }

    /**
     * Checks the queue can be reached before any thread starts, so a wrong host or
     * password gives one clear error instead of one per thread.
     */
    public void checkConnection() throws QueueException {
        try (JobQueue queue = queues.open()) {
            queue.size();
        }
    }

    /** Runs until {@link #stop()}, a fatal error, or (with {@code exitWhenEmpty}) an empty queue. Blocks. */
    public Exit run() throws InterruptedException {
        running = true;
        synchronized (workers) {
            for (int i = 1; i <= threads; i++) {
                Thread thread = new Thread(this::workLoop, "phishnet-queue-worker-" + i);
                workers.add(thread);
                thread.start();
            }
        }
        for (Thread thread : workers) {
            thread.join();
        }
        running = false;
        QueueException fatal = fatalError.get();
        return fatal == null ? Exit.STOPPED : Exit.FATAL_ERROR;
    }

    /**
     * Asks every thread to finish its current job and stop; safe from any thread (e.g. a
     * shutdown hook). Idle threads notice within one poll timeout; threads waiting to
     * reconnect are woken at once; a scan in progress is completed and recorded first.
     */
    public void stop() {
        running = false;
        synchronized (stopSignal) {
            stopSignal.notifyAll();
        }
    }

    public boolean isRunning() {
        return running;
    }

    private void workLoop() {
        JobQueue queue = null;
        Backoff backoff = new Backoff(RETRY_INITIAL, RETRY_MAX);
        try {
            while (running) {
                try {
                    if (queue == null) {
                        queue = queues.open();
                        backoff.reset();
                    }
                    var payload = queue.take(pollTimeout);
                    if (payload.isEmpty()) {
                        if (exitWhenEmpty) {
                            return;
                        }
                        continue;
                    }
                    process(payload.get());
                } catch (QueueException e) {
                    closeQuietly(queue);
                    queue = null;
                    if (!running) {
                        return;
                    }
                    if (!retry || e.isFatal()) {
                        if (fatalError.compareAndSet(null, e)) {
                            listener.fatal(e);
                        }
                        stop();
                        return;
                    }
                    Duration delay = backoff.nextDelay();
                    listener.connectionLost(e, delay, backoff.attempts());
                    try {
                        sleeper.sleep(delay);
                    } catch (InterruptedException interrupted) {
                        Thread.currentThread().interrupt();
                        return;
                    }
                }
            }
        } finally {
            closeQuietly(queue);
        }
    }

    private void process(String payload) {
        ScanJob job;
        try {
            job = ScanJob.parse(payload);
        } catch (ScanJob.InvalidJobException e) {
            listener.invalidJob(payload, e.getMessage());
            return;
        }
        UrlScanner.Result result;
        try {
            result = scanner.scan(job.target());
        } catch (RuntimeException e) {
            listener.jobFailed(job, e);
            return;
        }
        recorder.record(result);
        listener.scanned(job, result);
    }

    private static void closeQuietly(JobQueue queue) {
        if (queue != null) {
            queue.close();
        }
    }
}
