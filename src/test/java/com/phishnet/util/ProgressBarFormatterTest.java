package com.phishnet.util;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ProgressBarFormatterTest {

    @Test
    void zeroProgressShowsEmptyBar() {
        String line = ProgressBarFormatter.format(0, 30, 0);
        assertEquals("[--------------------] 0% (0/30)", line);
    }

    @Test
    void partialProgressFillsBarProportionally() {
        String line = ProgressBarFormatter.format(12, 30, 0);
        assertEquals("[########------------] 40% (12/30)", line);
    }

    @Test
    void completedProgressShowsFullBarAndNoEta() {
        String line = ProgressBarFormatter.format(30, 30, 5000);
        assertEquals("[####################] 100% (30/30)", line);
        assertFalse(line.contains("ETA"));
    }

    @Test
    void emptyBatchDoesNotDivideByZero() {
        String line = ProgressBarFormatter.format(0, 0, 0);
        assertEquals("[--------------------] 0% (0/0)", line);
    }

    @Test
    void etaIsOmittedWithoutElapsedTime() {
        String line = ProgressBarFormatter.format(5, 10, 0);
        assertFalse(line.contains("ETA"));
    }

    @Test
    void etaIsOmittedBeforeAnyProgress() {
        String line = ProgressBarFormatter.format(0, 10, 1000);
        assertFalse(line.contains("ETA"));
    }

    @Test
    void etaEstimatesRemainingTimeFromElapsedRate() {
        // 10 items in 10000ms -> 1000ms/item; 20 remaining -> 20000ms -> 0:20
        String line = ProgressBarFormatter.format(10, 30, 10_000);
        assertTrue(line.contains("ETA 0:20"), "expected ETA 0:20 in: " + line);
    }

    @Test
    void etaFormatsMinutesAndSeconds() {
        // 1 item in 65000ms -> remaining 1 item -> 65000ms -> 1:05
        String line = ProgressBarFormatter.format(1, 2, 65_000);
        assertTrue(line.contains("ETA 1:05"), "expected ETA 1:05 in: " + line);
    }

    @Test
    void completedNeverExceedsTotalInOutput() {
        String line = ProgressBarFormatter.format(999, 10, 0);
        assertEquals("[####################] 100% (10/10)", line);
    }

    @Test
    void negativeCompletedClampsToZero() {
        String line = ProgressBarFormatter.format(-5, 10, 0);
        assertEquals("[--------------------] 0% (0/10)", line);
    }
}
