package com.phishnet.cli;

import com.phishnet.model.DomainAgeResult;
import com.phishnet.model.RiskScore;
import com.phishnet.model.Signal;

import java.io.IOException;
import java.io.PrintStream;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.stream.Collectors;

/**
 * Appends one row per scan to a CSV history file, as a side effect of scanning.
 *
 * <p>This is deliberately kept out of {@link Reporter} and the analyzers: logging
 * happens regardless of {@code --verbose}/{@code --quiet}/{@code --json} output
 * mode, and a failure to write history must never abort a scan - it only prints a
 * warning to stderr and lets the run continue.
 *
 * <p>Rows are written incrementally (the file is opened and closed per row) so a
 * long {@code --batch} run that is interrupted still leaves partial history on disk.
 *
 * <p>Safe for concurrent use: appends are serialized across every writer in this JVM
 * (parallel batch scans, multi-threaded queue workers), and each append holds an
 * exclusive file lock, so separate processes appending to the same file (several
 * queue workers on one machine) can't interleave rows or write the header twice.
 */
public final class HistoryWriter {

    /** Whether a scanned target was a URL or an {@code .eml} file. */
    public enum TargetType {
        URL,
        EMAIL
    }

    static final String HEADER = "timestamp,target,type,risk_score,risk_label,signals,domain_age_days";

    /**
     * One lock for all writers in this JVM. A file lock is held per process, so two
     * writers here locking the same file at once would fail with
     * OverlappingFileLockException rather than wait; rows are tiny, so serializing
     * every append costs nothing measurable.
     */
    private static final Object APPEND_LOCK = new Object();

    private final Path file;
    private final boolean enabled;
    private final PrintStream err;

    /** Set once the first I/O error has been reported, so a batch run warns at most once. */
    private boolean warned;

    /**
     * @param file    destination CSV file (created if absent)
     * @param enabled when false, {@link #record} does nothing (used for {@code --no-history})
     * @param err     stream that I/O warnings are printed to
     */
    public HistoryWriter(Path file, boolean enabled, PrintStream err) {
        this.file = file;
        this.enabled = enabled;
        this.err = err;
    }

    /**
     * Appends one row for a completed scan. The header row is written first if the
     * file is new or empty. I/O errors are reported to stderr (once) and swallowed.
     */
    public void record(String target, TargetType type, RiskScore score) {
        record(target, type, score, DomainAgeResult.skipped());
    }

    /**
     * Like {@link #record(String, TargetType, RiskScore)}, with a domain age column:
     * whole days for a known age, {@code unknown} for a failed lookup, and empty
     * when no lookup was done ({@code --no-whois}, IP hosts, email scans).
     */
    public void record(String target, TargetType type, RiskScore score, DomainAgeResult domainAge) {
        if (!enabled) {
            return;
        }

        String signals = score.signals().stream()
                .map(Signal::id)
                .collect(Collectors.joining(";"));

        String row = String.join(",",
                csvField(Instant.now().toString()),
                csvField(target),
                csvField(type.name()),
                csvField(Integer.toString(score.score())),
                csvField(score.level().name()),
                csvField(signals),
                csvField(domainAgeField(domainAge)));

        synchronized (APPEND_LOCK) {
            try (FileChannel channel = FileChannel.open(file, StandardOpenOption.CREATE, StandardOpenOption.WRITE,
                    StandardOpenOption.APPEND);
                 FileLock lock = channel.lock()) {
                // Checked under the lock, so only the first of several concurrent writers adds the header.
                String text = (channel.size() == 0 ? HEADER + "\n" : "") + row + "\n";
                ByteBuffer bytes = ByteBuffer.wrap(text.getBytes(StandardCharsets.UTF_8));
                while (bytes.hasRemaining()) {
                    channel.write(bytes);
                }
            } catch (IOException e) {
                if (!warned) {
                    err.println("Warning: could not write scan history to " + file + ": " + e.getMessage());
                    warned = true;
                }
            }
        }
    }

    private static String domainAgeField(DomainAgeResult domainAge) {
        if (domainAge == null || domainAge.isSkipped()) {
            return "";
        }
        return domainAge.isKnown() ? Long.toString(domainAge.ageDays()) : "unknown";
    }

    /**
     * Escapes a single CSV field per RFC 4180: a field containing a comma, double
     * quote, CR, or LF is wrapped in double quotes with internal quotes doubled.
     */
    static String csvField(String value) {
        String v = value == null ? "" : value;
        if (v.indexOf(',') >= 0 || v.indexOf('"') >= 0 || v.indexOf('\n') >= 0 || v.indexOf('\r') >= 0) {
            return '"' + v.replace("\"", "\"\"") + '"';
        }
        return v;
    }
}
