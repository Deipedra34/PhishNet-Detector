package com.phishnet.queue;

/**
 * The job queue couldn't be used: the server is unreachable, the connection broke,
 * or it refused us. {@link #isFatal()} marks problems that reconnecting can't fix
 * (wrong password, missing permissions), which workers don't retry.
 */
public final class QueueException extends Exception {

    private final boolean fatal;

    public QueueException(String message, Throwable cause, boolean fatal) {
        super(message, cause);
        this.fatal = fatal;
    }

    public boolean isFatal() {
        return fatal;
    }
}
