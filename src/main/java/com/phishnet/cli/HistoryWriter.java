package com.phishnet.cli;

import com.phishnet.model.RiskScore;
import com.phishnet.model.Signal;

import java.io.BufferedWriter;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
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
 */
public final class HistoryWriter {

    /** Whether a scanned target was a URL or an {@code .eml} file. */
    public enum TargetType {
        URL,
        EMAIL
    }

    static final String HEADER = "timestamp,target,type,risk_score,risk_label,signals";

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
                csvField(signals));

        try {
            boolean needHeader = !Files.exists(file) || Files.size(file) == 0;
            try (BufferedWriter writer = Files.newBufferedWriter(file, StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND)) {
                if (needHeader) {
                    writer.write(HEADER);
                    writer.write("\n");
                }
                writer.write(row);
                writer.write("\n");
            }
        } catch (IOException e) {
            if (!warned) {
                err.println("Warning: could not write scan history to " + file + ": " + e.getMessage());
                warned = true;
            }
        }
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
