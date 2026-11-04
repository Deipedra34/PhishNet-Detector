package com.phishnet.queue;

import java.time.Duration;
import java.util.List;
import java.util.Optional;

/**
 * A FIFO queue of scan jobs shared between processes - a Redis list in practice
 * ({@link RedisJobQueue}), an in-memory fake in tests. One instance is one connection,
 * used by one thread.
 */
public interface JobQueue extends AutoCloseable {

    /** Appends jobs at the tail; returns the queue length afterwards. */
    long push(List<String> payloads) throws QueueException;

    /** Takes the oldest job, waiting up to {@code timeout}; empty if none arrived in time. */
    Optional<String> take(Duration timeout) throws QueueException;

    /** Jobs currently waiting. */
    long size() throws QueueException;

    /** Disconnects; never throws. */
    @Override
    void close();
}
