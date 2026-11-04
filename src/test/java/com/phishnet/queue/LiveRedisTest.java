package com.phishnet.queue;

import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Smoke test against a real Redis server - tagged "redis", so it's left out of the
 * default run and CI. Start one and opt in with:
 * <pre>
 * docker run -d --name phishnet-redis -p 6379:6379 redis
 * mvn test -Dgroups=redis -DexcludedGroups=none
 * </pre>
 * Set PHISHNET_TEST_REDIS_HOST / PHISHNET_TEST_REDIS_PORT to use a server elsewhere.
 * Uses a unique, throwaway queue name, so it never touches real jobs.
 */
@Tag("redis")
class LiveRedisTest {

    @Test
    void pushAndTakeAgainstARealServer() throws Exception {
        String host = System.getenv().getOrDefault("PHISHNET_TEST_REDIS_HOST", RedisSettings.DEFAULT_HOST);
        int port = Integer.parseInt(System.getenv().getOrDefault("PHISHNET_TEST_REDIS_PORT",
                Integer.toString(RedisSettings.DEFAULT_PORT)));
        RedisSettings settings = new RedisSettings(host, port, null, System.getenv("PHISHNET_REDIS_PASSWORD"), false,
                "phishnet:test:" + UUID.randomUUID());

        try (RedisJobQueue queue = RedisJobQueue.connect(settings)) {
            queue.push(List.of("first", "second"));

            assertEquals(Optional.of("first"), queue.take(Duration.ofSeconds(2)));
            assertEquals(Optional.of("second"), queue.take(Duration.ofSeconds(2)));
            assertEquals(0, queue.size());
        }
    }
}
