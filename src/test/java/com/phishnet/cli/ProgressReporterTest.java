package com.phishnet.cli;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ProgressReporterTest {

    private static PrintStream stream(ByteArrayOutputStream buffer) {
        return new PrintStream(buffer, true, StandardCharsets.UTF_8);
    }

    // --- forBatch: which listener a given run gets -----------------------------

    @Test
    void quietModeGetsNoopEvenOnATty() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        ProgressListener listener = ProgressReporter.forBatch(
                OutputLevel.QUIET, false, true, stream(out), stream(err), true);

        assertSame(ProgressListener.NOOP, listener);
    }

    @Test
    void nonTtyGetsNoopRegardlessOfOtherFlags() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        ProgressListener listener = ProgressReporter.forBatch(
                OutputLevel.NORMAL, false, false, stream(out), stream(err), true);

        assertSame(ProgressListener.NOOP, listener);
    }

    @Test
    void jsonModeRendersToStderrNotStdout() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        ProgressListener listener = ProgressReporter.forBatch(
                OutputLevel.NORMAL, true, true, stream(out), stream(err), true);

        listener.onProgress(1, 2);

        assertEquals("", out.toString(StandardCharsets.UTF_8));
        assertFalse(err.toString(StandardCharsets.UTF_8).isEmpty());
    }

    @Test
    void normalModeRendersToStdout() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        ProgressListener listener = ProgressReporter.forBatch(
                OutputLevel.NORMAL, false, true, stream(out), stream(err), true);

        listener.onProgress(1, 2);

        assertFalse(out.toString(StandardCharsets.UTF_8).isEmpty());
        assertEquals("", err.toString(StandardCharsets.UTF_8));
    }

    @Test
    void verboseModeAlsoRendersOnATty() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        ProgressListener listener = ProgressReporter.forBatch(
                OutputLevel.VERBOSE, false, true, stream(out), stream(err), true);

        assertTrue(listener != ProgressListener.NOOP);
    }

    // --- rendering behavior of ProgressReporter itself --------------------------

    @Test
    void onProgressUpdatesInPlaceWithCarriageReturnNotNewline() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ProgressReporter reporter = new ProgressReporter(stream(out), false);

        reporter.onProgress(1, 3);
        reporter.onProgress(2, 3);

        String text = out.toString(StandardCharsets.UTF_8);
        assertEquals(2, text.chars().filter(c -> c == '\r').count());
        assertFalse(text.contains("\n"));
    }

    @Test
    void onCompleteMovesToNewLine() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ProgressReporter reporter = new ProgressReporter(stream(out), false);

        reporter.onProgress(1, 1);
        reporter.onComplete();

        assertTrue(out.toString(StandardCharsets.UTF_8).endsWith(System.lineSeparator()));
    }

    @Test
    void noColorRenderingHasNoAnsiEscapeCodes() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ProgressReporter reporter = new ProgressReporter(stream(out), false);

        reporter.onProgress(1, 2);

        assertEquals(-1, out.toString(StandardCharsets.UTF_8).indexOf(''));
    }

    @Test
    void colorEnabledRenderingContainsAnsiEscapeCodes() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ProgressReporter reporter = new ProgressReporter(stream(out), true);

        reporter.onProgress(1, 2);

        assertTrue(out.toString(StandardCharsets.UTF_8).indexOf('') >= 0);
    }

    @Test
    void shorterSubsequentLineClearsLeftoverCharacters() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ProgressReporter reporter = new ProgressReporter(stream(out), false);

        reporter.onProgress(1000, 100000); // long line, e.g. "...(1000/100000)"
        String firstLine = out.toString(StandardCharsets.UTF_8).substring(1); // drop leading \r
        out.reset();

        reporter.onProgress(1, 1); // much shorter line, e.g. "...(1/1)"
        String secondRender = out.toString(StandardCharsets.UTF_8);
        String secondLine = secondRender.substring(1); // drop leading \r

        // The shorter line must be padded out to at least the previous line's
        // length so no leftover characters from the longer render remain visible.
        assertTrue(secondLine.length() >= firstLine.length(),
                "expected padding to cover leftover characters, got: [" + secondLine + "]");
        assertTrue(secondRender.contains("(1/1)"));
    }
}
