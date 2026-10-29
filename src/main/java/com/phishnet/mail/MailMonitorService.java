package com.phishnet.mail;

import com.phishnet.analyzer.EmailAnalyzer;
import com.phishnet.mail.MailSource.IncomingMail;
import com.phishnet.mail.MailSource.MoveOutcome;
import com.phishnet.model.EmailAnalysisResult;
import com.phishnet.model.RiskScore;
import com.phishnet.scoring.RiskScorer;
import jakarta.mail.AuthenticationFailedException;
import jakarta.mail.FolderClosedException;
import jakarta.mail.FolderNotFoundException;
import jakarta.mail.MessageRemovedException;
import jakarta.mail.MessagingException;
import jakarta.mail.NoSuchProviderException;
import jakarta.mail.StoreClosedException;

import java.io.IOException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

/**
 * Real-time mailbox monitoring: waits for new mail on a {@link MailSource}, runs
 * each new message through the same {@link EmailAnalyzer} and {@link RiskScorer}
 * as {@code phishnet --email}, and applies the configured {@link MonitorActions}.
 *
 * <p>The loop never gives up on a transient problem: a dropped connection, a
 * timeout, or a server error closes the source and reconnects after an
 * exponential {@link Backoff} delay. Only problems that retrying can't fix stop
 * it - rejected credentials (retrying could get the account locked), a folder
 * that doesn't exist, or a missing protocol provider.
 */
public final class MailMonitorService {

    /** How a {@link #run()} ended. */
    public enum Exit {
        /** {@link #stop()} was called (e.g. Ctrl+C). */
        STOPPED,
        /** A problem that reconnecting can't fix, reported through {@link Listener#fatal}. */
        FATAL_ERROR
    }

    /** One scanned message and what was done about it. */
    public record ScanResult(IncomingMail mail, EmailAnalysisResult analysis, RiskScore score,
                             MonitorActions.Plan plan, boolean truncated,
                             List<String> actionsTaken, List<String> actionFailures) {
    }

    /** Progress callbacks, for the CLI's output. Called on the monitor thread. */
    public interface Listener {
        void connecting(String mailbox, int attempt);

        void connected(String mailbox, boolean idle);

        void notice(String message);

        void scanned(ScanResult result);

        void messageFailed(IncomingMail mail, Exception error, boolean skipped);

        void connectionLost(Exception error, Duration retryIn, int attempt);

        void fatal(Exception error);

        void stopped();
    }

    /** Writes a scanned message to the scan history (CSV and/or SQLite). */
    public interface Recorder {
        void record(IncomingMail mail, EmailAnalysisResult analysis, RiskScore score);
    }

    /** {@link Thread#sleep}, swappable so tests don't actually wait. */
    public interface Sleeper {
        void sleep(Duration duration) throws InterruptedException;
    }

    /** A message that keeps failing is skipped after this many attempts, so it can't stall the monitor. */
    static final int MAX_ATTEMPTS_PER_MESSAGE = 3;

    private final MailSource source;
    private final EmailAnalyzer analyzer;
    private final RiskScorer scorer;
    private final MonitorActions actions;
    private final Recorder recorder;
    private final Listener listener;
    private final Duration pollInterval;
    private final Backoff backoff;
    private final Sleeper sleeper;
    private final int maxMessageBytes;

    private final Map<String, Integer> failedAttempts = new HashMap<>();
    private final CountDownLatch finished = new CountDownLatch(1);
    private volatile boolean running;
    private volatile Thread loopThread;

    public MailMonitorService(MailSource source, EmailAnalyzer analyzer, RiskScorer scorer, MonitorActions actions,
                              Recorder recorder, Listener listener, Duration pollInterval) {
        this(source, analyzer, scorer, actions, recorder, listener, pollInterval, new Backoff(),
                duration -> Thread.sleep(duration.toMillis()), MessageConverter.DEFAULT_MAX_BYTES);
    }

    MailMonitorService(MailSource source, EmailAnalyzer analyzer, RiskScorer scorer, MonitorActions actions,
                       Recorder recorder, Listener listener, Duration pollInterval, Backoff backoff,
                       Sleeper sleeper, int maxMessageBytes) {
        this.source = Objects.requireNonNull(source);
        this.analyzer = Objects.requireNonNull(analyzer);
        this.scorer = Objects.requireNonNull(scorer);
        this.actions = Objects.requireNonNull(actions);
        this.recorder = Objects.requireNonNull(recorder);
        this.listener = Objects.requireNonNull(listener);
        this.pollInterval = Objects.requireNonNull(pollInterval);
        this.backoff = Objects.requireNonNull(backoff);
        this.sleeper = Objects.requireNonNull(sleeper);
        this.maxMessageBytes = maxMessageBytes;
    }

    /** Monitors until {@link #stop()} or a fatal error. Blocks the calling thread. */
    public Exit run() {
        running = true;
        loopThread = Thread.currentThread();
        try {
            while (running) {
                try {
                    listener.connecting(source.describe(), backoff.attempts() + 1);
                    source.connect();
                    backoff.reset();
                    listener.connected(source.describe(), source.supportsIdle());
                    reportNotice();
                    while (running) {
                        for (IncomingMail mail : source.fetchNew()) {
                            if (!running) {
                                break;
                            }
                            process(mail);
                        }
                        reportNotice();
                        if (running) {
                            source.awaitNewMail(pollInterval);
                        }
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return Exit.STOPPED;
                } catch (MessagingException | RuntimeException e) {
                    source.close();
                    if (!running) {
                        return Exit.STOPPED;
                    }
                    if (isFatal(e)) {
                        listener.fatal(e);
                        return Exit.FATAL_ERROR;
                    }
                    Duration delay = backoff.nextDelay();
                    listener.connectionLost(e, delay, backoff.attempts());
                    try {
                        sleeper.sleep(delay);
                    } catch (InterruptedException interrupted) {
                        Thread.currentThread().interrupt();
                        return Exit.STOPPED;
                    }
                }
            }
            return Exit.STOPPED;
        } finally {
            running = false;
            source.close();
            listener.stopped();
            finished.countDown();
        }
    }

    /** Asks a running {@link #run()} to finish; safe from any thread (e.g. a shutdown hook). */
    public void stop() {
        running = false;
        source.wakeUp();
        Thread thread = loopThread;
        if (thread != null && thread != Thread.currentThread()) {
            thread.interrupt();
        }
    }

    /** Waits for {@link #run()} to return after {@link #stop()}. */
    public boolean awaitFinished(Duration timeout) throws InterruptedException {
        return finished.await(timeout.toMillis(), TimeUnit.MILLISECONDS);
    }

    public boolean isRunning() {
        return running;
    }

    // --- one message ---------------------------------------------------------------

    private void process(IncomingMail mail) throws MessagingException {
        MessageConverter.RawMessage raw;
        try {
            raw = MessageConverter.toRaw(mail.message(), maxMessageBytes);
        } catch (IOException | MessagingException | RuntimeException e) {
            if (isRemovedMessage(e)) {
                // Deleted by someone else between the check for new mail and reading it.
                source.acknowledge(mail);
                return;
            }
            if (isConnectionLoss(e)) {
                throw e instanceof MessagingException me ? me : new MessagingException(e.getMessage(), e);
            }
            failed(mail, e);
            return;
        }

        EmailAnalysisResult analysis;
        RiskScore score;
        try {
            analysis = analyzer.analyze(raw.stream());
            score = scorer.score(analysis.allSignals());
        } catch (RuntimeException e) {
            failed(mail, e);
            return;
        }

        MonitorActions.Plan plan = actions.decide(score.level());
        List<String> taken = new ArrayList<>();
        List<String> failures = new ArrayList<>();
        MessagingException connectionLoss = null;
        if (plan.record()) {
            recorder.record(mail, analysis, score);
            taken.add("recorded in scan history");
        }
        if (plan.flag()) {
            try {
                source.flagSuspicious(mail);
                taken.add("flagged");
            } catch (MessagingException e) {
                failures.add("flag: " + e.getMessage());
                connectionLoss = isConnectionLoss(e) ? e : null;
            }
        }
        if (plan.moveTo() != null && connectionLoss == null) {
            try {
                MoveOutcome outcome = source.move(mail, plan.moveTo());
                taken.add(switch (outcome) {
                    case MOVED, COPIED_AND_DELETED -> "moved to \"" + plan.moveTo() + "\"";
                    case COPIED_ONLY -> "copied to \"" + plan.moveTo()
                            + "\" (the server can't move messages safely, so the original was left in place)";
                });
            } catch (MessagingException e) {
                failures.add("move to \"" + plan.moveTo() + "\": " + e.getMessage());
                connectionLoss = isConnectionLoss(e) ? e : null;
            }
        }

        // Acknowledged before reporting a dropped connection, so the message isn't
        // scanned and recorded a second time after reconnecting.
        source.acknowledge(mail);
        failedAttempts.remove(mail.id());
        listener.scanned(new ScanResult(mail, analysis, score, plan, raw.truncated(),
                List.copyOf(taken), List.copyOf(failures)));
        if (connectionLoss != null) {
            throw connectionLoss;
        }
    }

    /** Reports a message that couldn't be scanned; gives up on it after a few tries. */
    private void failed(IncomingMail mail, Exception error) {
        int attempts = failedAttempts.merge(mail.id(), 1, Integer::sum);
        boolean skip = attempts >= MAX_ATTEMPTS_PER_MESSAGE;
        if (skip) {
            source.acknowledge(mail);
            failedAttempts.remove(mail.id());
        }
        listener.messageFailed(mail, error, skip);
    }

    private void reportNotice() {
        String notice = source.takeNotice();
        if (notice != null) {
            listener.notice(notice);
        }
    }

    // --- error classification ----------------------------------------------------

    /** Errors that retrying with the same settings can't fix. */
    static boolean isFatal(Exception e) {
        return e instanceof AuthenticationFailedException
                || e instanceof FolderNotFoundException
                || e instanceof NoSuchProviderException
                || e instanceof IllegalArgumentException;
    }

    /**
     * Errors meaning the connection itself is gone, rather than one message being bad.
     * Angus Mail reports a connection lost while streaming a message as an
     * {@link IOException} wrapping {@link FolderClosedException}, hence the cause walk.
     */
    static boolean isConnectionLoss(Exception e) {
        for (Throwable t = e; t != null; t = t.getCause()) {
            if (t instanceof FolderClosedException || t instanceof StoreClosedException
                    || t instanceof java.net.SocketException || t instanceof java.net.SocketTimeoutException
                    || t instanceof java.io.EOFException) {
                return true;
            }
        }
        return false;
    }

    /** The message was deleted (expunged) on the server before it could be read. */
    static boolean isRemovedMessage(Exception e) {
        for (Throwable t = e; t != null; t = t.getCause()) {
            if (t instanceof MessageRemovedException
                    || (t.getMessage() != null && t.getMessage().contains("expunged message"))) {
                return true;
            }
        }
        return false;
    }
}
