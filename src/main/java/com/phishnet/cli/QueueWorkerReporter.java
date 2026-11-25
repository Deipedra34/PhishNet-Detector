package com.phishnet.cli;

import com.phishnet.batch.UrlScanner;
import com.phishnet.i18n.Messages;
import com.phishnet.model.DomainAgeResult;
import com.phishnet.model.RiskLevel;
import com.phishnet.model.Signal;
import com.phishnet.queue.QueueException;
import com.phishnet.queue.QueueWorker;
import com.phishnet.queue.ScanJob;
import com.phishnet.util.AnsiColor;

import java.io.PrintStream;
import java.time.Clock;
import java.time.Duration;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.stream.Collectors;

/**
 * {@code phishnet queue worker}'s output, following the scan output conventions:
 * <ul>
 *   <li>QUIET - one {@code LEVEL SCORE TARGET} line per scanned job, nothing else on stdout</li>
 *   <li>NORMAL - one line per job, plus the signal ids for MEDIUM and HIGH results</li>
 *   <li>VERBOSE - every signal with its description, the domain age, and which thread scanned it</li>
 * </ul>
 * Warnings and connection problems go to stderr. Called from several worker threads at
 * once, so every method is synchronized - lines never interleave.
 */
final class QueueWorkerReporter implements QueueWorker.Listener {

    private static final DateTimeFormatter TIME = DateTimeFormatter.ofPattern("HH:mm:ss");
    private static final int MAX_PAYLOAD_SHOWN = 200;

    private final PrintStream out;
    private final PrintStream err;
    private final OutputLevel level;
    private final boolean color;
    private final Clock clock;
    private final Messages msg = Messages.current();

    private int scanned;
    private int high;
    private int medium;
    private int skipped;

    QueueWorkerReporter(PrintStream out, PrintStream err, OutputLevel level, boolean colorEnabled, Clock clock) {
        this.out = out;
        this.err = err;
        this.level = level;
        this.color = colorEnabled && level != OutputLevel.QUIET;
        this.clock = clock;
    }

    synchronized void header(String line) {
        if (level != OutputLevel.QUIET) {
            out.println(line);
        }
    }

    @Override
    public synchronized void scanned(ScanJob job, UrlScanner.Result result) {
        scanned++;
        RiskLevel risk = result.score().level();
        if (risk == RiskLevel.HIGH) {
            high++;
        } else if (risk == RiskLevel.MEDIUM) {
            medium++;
        }
        String target = MonitorReporter.clean(result.url(), msg.get("common.empty"));
        if (level == OutputLevel.QUIET) {
            out.println(risk.name() + " " + result.score().score() + " " + target);
            return;
        }
        String verdict = msg.get("risk." + risk.name()) + " " + result.score().score() + "/100";
        out.println("[" + now() + "] " + AnsiColor.apply(verdict, color, AnsiColor.BOLD, colorFor(risk)) + "  " + target);
        if (level == OutputLevel.VERBOSE) {
            out.println("  " + msg.get("queue.job", job.id().isEmpty() ? msg.get("queue.noId") : job.id(),
                    Thread.currentThread().getName()) + waited(job));
            DomainAgeResult age = result.domainAge();
            if (!age.isSkipped()) {
                out.println("  " + msg.get("queue.domainAge", age.formatAge()));
            }
            for (Signal signal : result.score().signals()) {
                out.println("  [" + signal.id() + "] " + signal.description()
                        + (signal.evidence().isEmpty() ? "" : " (" + MonitorReporter.clean(signal.evidence(), "") + ")"));
            }
        } else if (risk != RiskLevel.LOW && !result.score().signals().isEmpty()) {
            out.println("  " + msg.get("queue.signals", result.score().signals().stream().map(Signal::id)
                    .collect(Collectors.joining(", "))));
        }
    }

    private String waited(ScanJob job) {
        if (job.enqueuedAt() == null) {
            return "";
        }
        Duration waited = Duration.between(job.enqueuedAt(), clock.instant());
        return waited.isNegative() ? "" : msg.get("queue.queuedAgo", MonitorReporter.formatDuration(waited));
    }

    @Override
    public synchronized void invalidJob(String payload, String reason) {
        skipped++;
        String shown = MonitorReporter.clean(payload, msg.get("common.empty"));
        if (shown.length() > MAX_PAYLOAD_SHOWN) {
            shown = shown.substring(0, MAX_PAYLOAD_SHOWN) + "…";
        }
        err.println(msg.get("queue.invalidJob", reason, shown));
    }

    @Override
    public synchronized void jobFailed(ScanJob job, RuntimeException error) {
        skipped++;
        err.println(msg.get("queue.scanFailed", MonitorReporter.clean(job.target(), msg.get("common.empty")),
                MonitorReporter.describe(error)));
    }

    @Override
    public synchronized void connectionLost(QueueException error, Duration retryIn, int attempt) {
        String thread = Thread.currentThread().getName();
        String retry = MonitorReporter.formatDuration(retryIn);
        err.println("[" + now() + "] " + (attempt > 1
                ? msg.get("queue.connectionLost.attempt", thread, error.getMessage(), retry, attempt)
                : msg.get("queue.connectionLost", thread, error.getMessage(), retry)));
    }

    @Override
    public synchronized void fatal(QueueException error) {
        err.println(msg.get("cli.error", error.getMessage()));
        if (!error.isFatal()) {
            err.println(QueueCommand.unreachableHint());
            err.println(msg.get("queue.retryHint"));
        }
    }

    synchronized void stopped() {
        if (level != OutputLevel.QUIET) {
            out.println("[" + now() + "] " + (skipped > 0
                    ? msg.get("queue.stopped.skipped", scanned, high, medium, skipped)
                    : msg.get("queue.stopped", scanned, high, medium)));
        }
    }

    synchronized int scannedCount() {
        return scanned;
    }

    private String now() {
        return LocalTime.now(clock).format(TIME);
    }

    private static AnsiColor colorFor(RiskLevel level) {
        return switch (level) {
            case HIGH -> AnsiColor.RED;
            case MEDIUM -> AnsiColor.YELLOW;
            case LOW -> AnsiColor.GREEN;
        };
    }
}
