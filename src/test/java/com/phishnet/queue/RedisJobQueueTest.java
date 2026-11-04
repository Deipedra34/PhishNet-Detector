package com.phishnet.queue;

import com.github.fppt.jedismock.RedisServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.ServerSocket;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.stream.IntStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link RedisJobQueue} over the real Redis protocol, against jedis-mock - an
 * in-process, pure-Java Redis server - so no Redis installation is needed.
 */
class RedisJobQueueTest {

    private RedisServer server;
    private RedisSettings settings;
    /**
     * jedis-mock lowercases command names with the JVM's default locale, so under a
     * Turkish locale "PING" becomes "pıng" and is rejected. That's the fake server's
     * bug (real Redis is unaffected); run these tests under the root locale.
     */
    private Locale originalLocale;

    @BeforeEach
    void startServer() throws IOException {
        originalLocale = Locale.getDefault();
        Locale.setDefault(Locale.ROOT);
        server = RedisServer.newRedisServer().start();
        settings = new RedisSettings(server.getHost(), server.getBindPort(), null, null, false, "test:jobs");
    }

    @AfterEach
    void stopServer() throws IOException {
        server.stop();
        Locale.setDefault(originalLocale);
    }

    @Test
    void jobsComeOutInTheOrderTheyWentIn() throws Exception {
        try (RedisJobQueue producer = RedisJobQueue.connect(settings);
             RedisJobQueue consumer = RedisJobQueue.connect(settings)) {
            assertEquals(3, producer.push(List.of("a", "b", "c")));
            assertEquals(3, consumer.size());

            assertEquals(Optional.of("a"), consumer.take(Duration.ofSeconds(1)));
            assertEquals(Optional.of("b"), consumer.take(Duration.ofSeconds(1)));
            assertEquals(Optional.of("c"), consumer.take(Duration.ofSeconds(1)));
            assertEquals(0, consumer.size());
        }
    }

    @Test
    void takeTimesOutOnAnEmptyQueue() throws Exception {
        try (RedisJobQueue queue = RedisJobQueue.connect(settings)) {
            long start = System.nanoTime();
            assertEquals(Optional.empty(), queue.take(Duration.ofSeconds(1)));
            assertTrue(System.nanoTime() - start >= Duration.ofMillis(900).toNanos(), "it actually blocked");
        }
    }

    @Test
    void largePushesAreSplitIntoChunksWithoutLosingOrder() throws Exception {
        List<String> payloads = IntStream.range(0, RedisJobQueue.PUSH_CHUNK * 2 + 17).mapToObj(i -> "job-" + i).toList();
        try (RedisJobQueue queue = RedisJobQueue.connect(settings)) {
            assertEquals(payloads.size(), queue.push(payloads));
            List<String> taken = new ArrayList<>();
            for (int i = 0; i < payloads.size(); i++) {
                taken.add(queue.take(Duration.ofSeconds(1)).orElseThrow());
            }
            assertEquals(payloads, taken);
        }
    }

    @Test
    void eachJobGoesToExactlyOneOfSeveralConsumers() throws Exception {
        List<String> payloads = IntStream.range(0, 300).mapToObj(i -> "job-" + i).toList();
        try (RedisJobQueue producer = RedisJobQueue.connect(settings)) {
            producer.push(payloads);
        }
        List<String> taken = java.util.Collections.synchronizedList(new ArrayList<>());
        List<Thread> consumers = new ArrayList<>();
        for (int c = 0; c < 4; c++) {
            Thread thread = new Thread(() -> {
                try (RedisJobQueue queue = RedisJobQueue.connect(settings)) {
                    for (Optional<String> job = queue.take(Duration.ofSeconds(1)); job.isPresent();
                         job = queue.take(Duration.ofSeconds(1))) {
                        taken.add(job.get());
                    }
                } catch (QueueException e) {
                    throw new IllegalStateException(e);
                }
            });
            consumers.add(thread);
            thread.start();
        }
        for (Thread thread : consumers) {
            thread.join(30_000);
        }

        assertEquals(300, taken.size());
        assertEquals(java.util.Set.copyOf(payloads), java.util.Set.copyOf(taken));
    }

    @Test
    void unreachableServerGivesAClearNonFatalError() throws Exception {
        int closedPort;
        try (ServerSocket socket = new ServerSocket(0)) {
            closedPort = socket.getLocalPort();
        }
        RedisSettings nowhere = new RedisSettings("127.0.0.1", closedPort, null, null, false, "test:jobs");

        QueueException error = assertThrows(QueueException.class, () -> RedisJobQueue.connect(nowhere));

        assertTrue(error.getMessage().startsWith("can't reach Redis at 127.0.0.1:" + closedPort), error.getMessage());
        assertFalse(error.isFatal(), "worth retrying");
    }

    @Test
    void wrongTypeAtTheQueueKeyIsFatal() throws Exception {
        try (redis.clients.jedis.Jedis raw = new redis.clients.jedis.Jedis(server.getHost(), server.getBindPort());
             RedisJobQueue queue = RedisJobQueue.connect(settings)) {
            raw.set("test:jobs", "not a list");

            QueueException error = assertThrows(QueueException.class, () -> queue.push(List.of("x")));

            assertTrue(error.isFatal(), error.getMessage());
            assertTrue(error.getMessage().contains("WRONGTYPE"), error.getMessage());
        }
    }
}
