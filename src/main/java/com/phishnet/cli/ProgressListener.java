package com.phishnet.cli;

/**
 * Callback the batch-scanning loop reports progress through, so it never has
 * to know whether a progress bar is actually being rendered anywhere - it
 * just calls {@link #onProgress} once per scanned item and {@link #onComplete}
 * when the batch is done. Use {@link #NOOP} when progress reporting is
 * disabled (--quiet, --json to stdout, or a non-TTY destination).
 */
public interface ProgressListener {

    ProgressListener NOOP = new ProgressListener() {
        @Override
        public void onProgress(int completed, int total) {
        }
    };

    void onProgress(int completed, int total);

    default void onComplete() {
    }
}
