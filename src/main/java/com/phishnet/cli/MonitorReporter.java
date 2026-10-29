package com.phishnet.cli;

import com.phishnet.mail.MailMonitorService;
import com.phishnet.mail.MailMonitorService.ScanResult;
import com.phishnet.mail.MailSource.IncomingMail;
import com.phishnet.model.EmailAnalysisResult;
import com.phishnet.model.RiskLevel;
import com.phishnet.model.Signal;
import com.phishnet.util.AnsiColor;
import jakarta.mail.AuthenticationFailedException;

import java.io.PrintStream;
import java.time.Clock;
import java.time.Duration;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.List;

/**
 * {@code phishnet monitor}'s output, following the scan output conventions:
 * <ul>
 *   <li>QUIET - one {@code LEVEL SCORE LABEL} line per scanned message, nothing else on stdout</li>
 *   <li>NORMAL - status lines, one line per message, and the signals and actions for suspicious ones</li>
 *   <li>VERBOSE - also the signals of every message, its mailbox label, and connection attempts</li>
 * </ul>
 * Connection problems and warnings go to stderr at every level. Nothing here ever
 * sees the password.
 */
final class MonitorReporter implements MailMonitorService.Listener {

    private static final DateTimeFormatter TIME = DateTimeFormatter.ofPattern("HH:mm:ss");
    private static final int MAX_FIELD_LENGTH = 120;

    private final PrintStream out;
    private final PrintStream err;
    private final OutputLevel level;
    private final boolean color;
    private final Clock clock;
    private final String waitDescription;

    private int scanned;
    private int suspicious;

    /**
     * @param waitDescription how new mail is waited for when IDLE isn't available,
     *                        e.g. "polling every 60s"
     */
    MonitorReporter(PrintStream out, PrintStream err, OutputLevel level, boolean colorEnabled, Clock clock,
                    String waitDescription) {
        this.out = out;
        this.err = err;
        this.level = level;
        this.color = colorEnabled && level != OutputLevel.QUIET;
        this.clock = clock;
        this.waitDescription = waitDescription;
    }

    /** Printed once before monitoring starts (NORMAL and VERBOSE only). */
    void header(List<String> lines) {
        if (level == OutputLevel.QUIET) {
            return;
        }
        lines.forEach(out::println);
    }

    // --- MailMonitorService.Listener -------------------------------------------------

    @Override
    public void connecting(String mailbox, int attempt) {
        if (level == OutputLevel.VERBOSE) {
            status("Connecting to " + mailbox + (attempt > 1 ? " (attempt " + attempt + ")" : "") + "...");
        }
    }

    @Override
    public void connected(String mailbox, boolean idle) {
        if (level != OutputLevel.QUIET) {
            status("Connected. Waiting for new mail ("
                    + (idle ? "IMAP IDLE - near real time" : waitDescription) + ").");
        }
    }

    @Override
    public void notice(String message) {
        if (level == OutputLevel.QUIET) {
            err.println("Note: " + message);
        } else {
            status("Note: " + message);
        }
    }

    @Override
    public void scanned(ScanResult result) {
        scanned++;
        if (result.plan().suspicious()) {
            suspicious++;
        }
        RiskLevel risk = result.score().level();
        if (level == OutputLevel.QUIET) {
            out.println(risk.name() + " " + result.score().score() + " " + result.mail().label());
        } else {
            printResult(result);
        }
        for (String failure : result.actionFailures()) {
            err.println("Warning: could not " + failure + " (" + result.mail().label() + ")");
        }
    }

    private void printResult(ScanResult result) {
        EmailAnalysisResult analysis = result.analysis();
        RiskLevel risk = result.score().level();
        boolean flagged = result.plan().suspicious();
        String verdict = (flagged ? symbolFor(risk) + " " : "") + risk.name() + " " + result.score().score() + "/100";
        out.println("[" + now() + "] " + AnsiColor.apply(verdict, color, AnsiColor.BOLD, colorFor(risk))
                + "  From: " + sender(analysis) + "  Subject: " + clean(analysis.subject(), "(no subject)"));

        boolean details = flagged || level == OutputLevel.VERBOSE;
        if (level == OutputLevel.VERBOSE) {
            out.println("  Message: " + result.mail().label()
                    + ", links inspected: " + analysis.linkResults().size()
                    + (result.truncated() ? ", analyzed the first 10 MB only" : ""));
        }
        if (details && !result.score().signals().isEmpty()) {
            for (Signal signal : result.score().signals()) {
                StringBuilder line = new StringBuilder("  ")
                        .append(AnsiColor.apply(symbolFor(risk), color, colorFor(risk)))
                        .append(" [").append(signal.id()).append("] ").append(signal.description());
                if (level == OutputLevel.VERBOSE && !signal.evidence().isEmpty()) {
                    line.append(" (").append(clean(signal.evidence(), "")).append(")");
                }
                out.println(line);
            }
        }
        if (flagged) {
            out.println("  " + result.score().recommendation());
        }
        if (!result.actionsTaken().isEmpty() && (flagged || level == OutputLevel.VERBOSE)) {
            out.println("  Actions: " + String.join(", ", result.actionsTaken()));
        }
    }

    @Override
    public void messageFailed(IncomingMail mail, Exception error, boolean skipped) {
        err.println("Warning: could not scan " + mail.label() + ": " + describe(error)
                + (skipped ? " - skipping it" : " - will try again"));
    }

    @Override
    public void connectionLost(Exception error, Duration retryIn, int attempt) {
        err.println("[" + now() + "] Connection problem: " + describe(error) + ". Reconnecting in "
                + formatDuration(retryIn) + (attempt > 1 ? " (attempt " + attempt + ")" : "") + "...");
    }

    @Override
    public void fatal(Exception error) {
        if (error instanceof AuthenticationFailedException) {
            err.println("Error: the mail server rejected the login: " + describe(error));
            err.println("Check the username and password. Gmail, Outlook.com, iCloud, and Yahoo require an "
                    + "app password (or --oauth2 with an access token), not your regular account password.");
        } else {
            err.println("Error: " + describe(error));
        }
    }

    @Override
    public void stopped() {
        if (level != OutputLevel.QUIET) {
            status("Monitoring stopped. Scanned " + scanned + " message(s), " + suspicious + " suspicious.");
        }
    }

    int scannedCount() {
        return scanned;
    }

    int suspiciousCount() {
        return suspicious;
    }

    // --- formatting -------------------------------------------------------------------

    private void status(String message) {
        out.println("[" + now() + "] " + message);
    }

    private String now() {
        return LocalTime.now(clock).format(TIME);
    }

    private static String sender(EmailAnalysisResult analysis) {
        String address = clean(analysis.senderAddress(), "");
        String name = clean(analysis.displayName(), "");
        if (address.isEmpty()) {
            return name.isEmpty() ? "(unknown sender)" : name;
        }
        return name.isEmpty() ? "<" + address + ">" : name + " <" + address + ">";
    }

    /**
     * Header values come from whoever sent the mail: strip control characters (so a
     * crafted subject can't fake extra output lines or terminal escapes) and cap the length.
     */
    static String clean(String value, String fallback) {
        if (value == null || value.isBlank()) {
            return fallback;
        }
        String flat = value.replaceAll("\\p{Cntrl}+", " ").strip();
        return flat.length() > MAX_FIELD_LENGTH ? flat.substring(0, MAX_FIELD_LENGTH - 1) + "…" : flat;
    }

    /** An exception's message, readable even when it has none. */
    static String describe(Throwable error) {
        String message = error.getMessage();
        if (message == null || message.isBlank()) {
            Throwable cause = error.getCause();
            return cause != null && cause != error ? describe(cause) : error.getClass().getSimpleName();
        }
        return clean(message, error.getClass().getSimpleName());
    }

    static String formatDuration(Duration duration) {
        long seconds = duration.toSeconds();
        if (seconds < 60) {
            return seconds + "s";
        }
        long minutes = seconds / 60;
        long rest = seconds % 60;
        return rest == 0 ? minutes + "m" : minutes + "m " + rest + "s";
    }

    private static AnsiColor colorFor(RiskLevel level) {
        return switch (level) {
            case HIGH -> AnsiColor.RED;
            case MEDIUM -> AnsiColor.YELLOW;
            case LOW -> AnsiColor.GREEN;
        };
    }

    private static String symbolFor(RiskLevel level) {
        return level == RiskLevel.HIGH ? "✗" : "⚠";
    }
}
