package com.phishnet.queue;

import redis.clients.jedis.HostAndPort;
import redis.clients.jedis.Jedis;
import redis.clients.jedis.exceptions.JedisConnectionException;
import redis.clients.jedis.exceptions.JedisDataException;
import redis.clients.jedis.exceptions.JedisException;

import java.time.Duration;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

/**
 * The job queue as a Redis list: producers {@code LPUSH} onto the head, workers
 * {@code BRPOP} from the tail, which makes it first-in, first-out. Each job goes to
 * exactly one worker, however many are connected.
 *
 * <p>Delivery is at-most-once: {@code BRPOP} removes a job as it hands it out, so a
 * job a worker was in the middle of when it was killed is not redelivered.
 */
public final class RedisJobQueue implements JobQueue {

    /** LPUSH this many jobs per command, so a huge file doesn't become one huge request. */
    static final int PUSH_CHUNK = 500;

    private final RedisSettings settings;
    private final Jedis jedis;

    private RedisJobQueue(RedisSettings settings, Jedis jedis) {
        this.settings = settings;
        this.jedis = jedis;
    }

    /** Connects, authenticates, and checks the server answers (PING). */
    public static RedisJobQueue connect(RedisSettings settings) throws QueueException {
        Jedis jedis = null;
        try {
            jedis = new Jedis(new HostAndPort(settings.host(), settings.port()), settings.clientConfig());
            jedis.ping();
            return new RedisJobQueue(settings, jedis);
        } catch (JedisException | IllegalArgumentException e) {
            if (jedis != null) {
                closeQuietly(jedis);
            }
            throw translate(settings, e);
        }
    }

    @Override
    public long push(List<String> payloads) throws QueueException {
        try {
            long length = jedis.llen(settings.queueKey());
            for (int from = 0; from < payloads.size(); from += PUSH_CHUNK) {
                List<String> chunk = payloads.subList(from, Math.min(payloads.size(), from + PUSH_CHUNK));
                length = jedis.lpush(settings.queueKey(), chunk.toArray(String[]::new));
            }
            return length;
        } catch (JedisException e) {
            throw translate(settings, e);
        }
    }

    @Override
    public Optional<String> take(Duration timeout) throws QueueException {
        int seconds = (int) Math.max(1, Math.min(Integer.MAX_VALUE, timeout.toSeconds()));
        try {
            // [key, value], or null when nothing arrived within the timeout.
            List<String> popped = jedis.brpop(seconds, settings.queueKey());
            return popped == null || popped.size() < 2 ? Optional.empty() : Optional.of(popped.get(1));
        } catch (JedisException e) {
            throw translate(settings, e);
        }
    }

    @Override
    public long size() throws QueueException {
        try {
            return jedis.llen(settings.queueKey());
        } catch (JedisException e) {
            throw translate(settings, e);
        }
    }

    @Override
    public void close() {
        closeQuietly(jedis);
    }

    private static void closeQuietly(Jedis jedis) {
        try {
            jedis.close();
        } catch (RuntimeException ignored) {
            // already broken
        }
    }

    /** A readable message; authentication and permission errors are marked fatal. */
    static QueueException translate(RedisSettings settings, Exception e) {
        String where = settings.host() + ":" + settings.port();
        String detail = e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage();
        if (e instanceof JedisConnectionException) {
            return new QueueException("can't reach Redis at " + where + ": " + rootMessage(e), e, false);
        }
        String upper = detail.toUpperCase(Locale.ROOT);
        boolean fatal = e instanceof JedisDataException
                && (upper.startsWith("WRONGPASS") || upper.startsWith("NOAUTH") || upper.startsWith("NOPERM")
                || upper.contains("INVALID PASSWORD") || upper.contains("WRONGTYPE"));
        return new QueueException("Redis at " + where + " refused the request: " + detail, e, fatal);
    }

    private static String rootMessage(Throwable e) {
        Throwable root = e;
        while (root.getCause() != null && root.getCause() != root) {
            root = root.getCause();
        }
        String message = root.getMessage();
        return message == null || message.isBlank() ? root.getClass().getSimpleName() : message;
    }
}
