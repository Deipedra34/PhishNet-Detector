package com.phishnet.queue;

import redis.clients.jedis.DefaultJedisClientConfig;
import redis.clients.jedis.JedisClientConfig;

import java.util.Objects;

/**
 * Where the shared job queue lives: a Redis server and the name of the list used as
 * the queue. {@link #toString()} never shows the password.
 *
 * @param host     Redis host
 * @param port     Redis port
 * @param username ACL user name, or null for the default user
 * @param password password, or null when the server has none
 * @param ssl      connect with TLS
 * @param queueKey name of the Redis list holding the jobs
 */
public record RedisSettings(String host, int port, String username, String password, boolean ssl,
                            String queueKey) {

    public static final String DEFAULT_HOST = "localhost";
    public static final int DEFAULT_PORT = 6379;
    public static final String DEFAULT_QUEUE = "phishnet:jobs";

    static final int CONNECT_TIMEOUT_MILLIS = 5_000;
    static final int SOCKET_TIMEOUT_MILLIS = 10_000;

    public RedisSettings {
        Objects.requireNonNull(host, "host");
        Objects.requireNonNull(queueKey, "queueKey");
        if (port < 1 || port > 65535) {
            throw new IllegalArgumentException("port must be 1-65535, got " + port);
        }
        if (queueKey.isBlank()) {
            throw new IllegalArgumentException("queue name must not be blank");
        }
        username = username == null || username.isBlank() ? null : username;
        password = password == null || password.isEmpty() ? null : password;
    }

    JedisClientConfig clientConfig() {
        DefaultJedisClientConfig.Builder builder = DefaultJedisClientConfig.builder()
                .connectionTimeoutMillis(CONNECT_TIMEOUT_MILLIS)
                .socketTimeoutMillis(SOCKET_TIMEOUT_MILLIS)
                .ssl(ssl)
                // Plain RESP2 is all LPUSH/BRPOP need; skips Jedis's per-connection warning about RESP3.
                .autoNegotiateProtocol(false)
                .clientName("phishnet");
        if (username != null) {
            builder.user(username);
        }
        if (password != null) {
            builder.password(password);
        }
        return builder.build();
    }

    /** "redis list "phishnet:jobs" on localhost:6379" - for messages. */
    public String describe() {
        return "Redis list \"" + queueKey + "\" on " + host + ":" + port + (ssl ? " (TLS)" : "");
    }

    @Override
    public String toString() {
        return "RedisSettings[host=" + host + ", port=" + port + ", username=" + username
                + ", password=" + (password == null ? "none" : "<redacted>") + ", ssl=" + ssl
                + ", queueKey=" + queueKey + "]";
    }
}
