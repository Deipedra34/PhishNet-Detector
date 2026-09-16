package com.phishnet.cli;

import com.phishnet.util.AnsiColor;
import com.phishnet.util.ProgressBarFormatter;

import java.io.PrintStream;

/**
 * Renders a live-updating progress bar by redrawing a single line with '\r'
 * (no cursor-positioning escape codes needed for that). Scanning code never
 * touches this class directly - it only sees the {@link ProgressListener}
 * interface, and {@link #forBatch} decides which implementation (this one,
 * or {@link ProgressListener#NOOP}) a given run should get.
 */
public final class ProgressReporter implements ProgressListener {

    private final PrintStream stream;
    private final boolean colorEnabled;
    private final long startNanos = System.nanoTime();
    private int lastLineLength;

    public ProgressReporter(PrintStream stream, boolean colorEnabled) {
        this.stream = stream;
        this.colorEnabled = colorEnabled;
    }

    /**
     * Decides where (or whether) batch progress should render:
     * <ul>
     *   <li>{@code --quiet} or a non-TTY stdout (piped/redirected) -&gt; {@link ProgressListener#NOOP},
     *       since redrawing a line makes no sense outside an interactive terminal</li>
     *   <li>{@code --json} -&gt; renders to stderr, so it never corrupts JSON piped from stdout</li>
     *   <li>otherwise -&gt; renders to stdout, ahead of the normal per-item/summary output that
     *       the batch loop prints once scanning finishes</li>
     * </ul>
     */
    public static ProgressListener forBatch(OutputLevel level, boolean json, boolean isTty,
                                             PrintStream out, PrintStream err, boolean colorEnabled) {
        if (level == OutputLevel.QUIET || !isTty) {
            return ProgressListener.NOOP;
        }
        return new ProgressReporter(json ? err : out, colorEnabled);
    }

    @Override
    public void onProgress(int completed, int total) {
        long elapsedMillis = (System.nanoTime() - startNanos) / 1_000_000;
        String line = ProgressBarFormatter.format(completed, total, elapsedMillis);
        String rendered = AnsiColor.apply(line, colorEnabled, AnsiColor.BOLD);
        stream.print("\r" + rendered + clearTrailing(line.length()));
        stream.flush();
        lastLineLength = line.length();
    }

    @Override
    public void onComplete() {
        stream.println();
    }

    /** Blanks out any leftover characters from a previous, longer render of the line. */
    private String clearTrailing(int currentLength) {
        int diff = lastLineLength - currentLength;
        return diff > 0 ? " ".repeat(diff) : "";
    }
}
