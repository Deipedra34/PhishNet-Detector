package com.phishnet.cli;

import com.github.fppt.jedismock.RedisServer;
import com.phishnet.analyzer.WhoisClient;
import com.phishnet.history.HistoryDatabase;
import com.phishnet.history.HistoryEntry;
import com.phishnet.history.HistoryFilter;
import com.phishnet.queue.RedisJobQueue;
import com.phishnet.queue.RedisSettings;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import picocli.CommandLine;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@code phishnet queue produce|worker} end to end against jedis-mock, an in-process
 * Redis server: real Jedis connections, real LPUSH/BRPOP, no Redis installation.
 */
class QueueCommandTest {

    private record Captured(int exitCode, String stdout, String stderr) {
    }

    private static final WhoisClient OFFLINE_WHOIS = (server, query, timeout) -> {
        throw new IOException("network disabled in tests");
    };

    @TempDir
    Path tempDir;

    private RedisServer redis;
    private final Map<String, String> env = new HashMap<>();
    /**
     * jedis-mock lowercases command names with the JVM's default locale, so under a
     * Turkish locale "PING" becomes "pıng" and is rejected. That's the fake server's
     * bug (real Redis is unaffected); run these tests under the root locale.
     */
    private Locale originalLocale;

    @BeforeEach
    void startRedis() throws IOException {
        originalLocale = Locale.getDefault();
        Locale.setDefault(Locale.ROOT);
        redis = RedisServer.newRedisServer().start();
    }

    @AfterEach
    void stopRedis() throws IOException {
        redis.stop();
        Locale.setDefault(originalLocale);
    }

    /** Settings of every connection the commands opened. */
    private final List<RedisSettings> connections = java.util.Collections.synchronizedList(new ArrayList<>());

    private Captured queue(String... args) {
        ByteArrayOutputStream outBytes = new ByteArrayOutputStream();
        ByteArrayOutputStream errBytes = new ByteArrayOutputStream();
        try (PrintStream out = new PrintStream(outBytes, true, StandardCharsets.UTF_8);
             PrintStream err = new PrintStream(errBytes, true, StandardCharsets.UTF_8)) {
            CommandLine cmd = QueueCommand.commandLine(new QueueCommand.Environment(out, err, env, OFFLINE_WHOIS,
                    settings -> {
                        connections.add(settings);
                        return RedisJobQueue.connect(settings);
                    },
                    Clock.fixed(Instant.parse("2026-11-04T10:00:00Z"), ZoneOffset.UTC), false));
            cmd.setOut(new PrintWriter(out, true, StandardCharsets.UTF_8));
            cmd.setErr(new PrintWriter(err, true, StandardCharsets.UTF_8));
            int code = cmd.execute(args);
            return new Captured(code, outBytes.toString(StandardCharsets.UTF_8), errBytes.toString(StandardCharsets.UTF_8));
        }
    }

    private String[] at(String... args) {
        List<String> all = new ArrayList<>(Arrays.asList(args));
        all.addAll(List.of("--redis-host", redis.getHost(), "--redis-port", Integer.toString(redis.getBindPort())));
        return all.toArray(String[]::new);
    }

    private String[] worker(String name, String... extra) {
        List<String> all = new ArrayList<>(List.of("worker", "--exit-when-empty", "--no-whois", "--no-color",
                "--history-file", tempDir.resolve(name + ".csv").toString(),
                "--history-db", tempDir.resolve(name + ".db").toString()));
        all.addAll(Arrays.asList(extra));
        return at(all.toArray(String[]::new));
    }

    private Path urlFile(int count) throws IOException {
        List<String> lines = new ArrayList<>(List.of("# phishing test list", ""));
        lines.addAll(IntStream.range(0, count).mapToObj(i -> "http://site-" + i + ".tk/login").toList());
        Path file = tempDir.resolve("urls.txt");
        Files.write(file, lines, StandardCharsets.UTF_8);
        return file;
    }

    private Set<String> csvTargets(String name) throws IOException {
        List<String> lines = Files.readAllLines(tempDir.resolve(name + ".csv"));
        return lines.subList(1, lines.size()).stream().map(line -> line.split(",")[1]).collect(Collectors.toSet());
    }

    private List<HistoryEntry> dbEntries(String name) throws Exception {
        return new HistoryDatabase(tempDir.resolve(name + ".db"), false, System.err).search(HistoryFilter.recent(0));
    }

    @Test
    void produceThenWorkerScansEveryUrlExactlyOnce() throws Exception {
        Captured produced = queue(at("produce", "--file", urlFile(50).toString()));

        assertEquals(0, produced.exitCode(), produced.stderr());
        assertTrue(produced.stdout().contains("Queued 50 job(s) on Redis list \"phishnet:jobs\" on "), produced.stdout());

        Captured worked = queue(worker("w", "--threads", "4"));

        assertEquals(0, worked.exitCode(), worked.stderr());
        assertEquals(50, csvTargets("w").size());
        assertEquals(51, Files.readAllLines(tempDir.resolve("w.csv")).size(), "header + one row per URL");
        assertEquals(50, dbEntries("w").size());
        assertTrue(worked.stdout().contains("PhishNet queue worker: 4 thread(s) taking jobs from"), worked.stdout());
        assertTrue(worked.stdout().contains("Worker stopped. Scanned 50 job(s)"), worked.stdout());
        assertTrue(worked.stdout().contains("  signals: suspiciousTld"), worked.stdout());
    }

    @Test
    void twoWorkersSplitTheQueueWithoutOverlap() throws Exception {
        queue(at("produce", "--file", urlFile(120).toString()));

        // Two worker processes (two "machines"), each with its own history files.
        AtomicReference<Captured> second = new AtomicReference<>();
        Thread other = new Thread(() -> second.set(queue(worker("b", "--threads", "3"))));
        other.start();
        Captured first = queue(worker("a", "--threads", "3"));
        other.join(60_000);

        assertEquals(0, first.exitCode(), first.stderr());
        assertEquals(0, second.get().exitCode(), second.get().stderr());
        Set<String> a = csvTargets("a");
        Set<String> b = csvTargets("b");
        Set<String> overlap = new HashSet<>(a);
        overlap.retainAll(b);
        assertTrue(overlap.isEmpty(), "a job was scanned by both workers: " + overlap);
        assertEquals(120, a.size() + b.size(), "no job lost");
    }

    @Test
    void quietWorkerPrintsOneLinePerJob() throws Exception {
        queue(at("produce", "--file", urlFile(3).toString(), "--quiet"));

        Captured worked = queue(worker("q", "--threads", "1", "--quiet"));

        List<String> lines = worked.stdout().lines().toList();
        assertEquals(3, lines.size(), worked.stdout());
        assertTrue(lines.stream().allMatch(line -> line.matches("(MEDIUM|HIGH) \\d+ http://site-\\d\\.tk/login")),
                lines.toString());
    }

    @Test
    void verboseWorkerShowsSignalDetailsAndQueueTime() throws Exception {
        queue(at("produce", "--file", urlFile(1).toString()));

        String out = queue(worker("v", "--threads", "1", "--verbose")).stdout();

        assertTrue(out.contains("on phishnet-queue-worker-1, queued 0s ago"), out);
        assertTrue(out.contains("[suspiciousTld] URL uses a TLD commonly abused for phishing (.tk)"), out);
    }

    @Test
    void customQueueNamesAreIndependent() throws Exception {
        queue(at("produce", "--file", urlFile(5).toString(), "--queue", "team-a"));

        Captured wrongQueue = queue(worker("x", "--threads", "1"));
        Captured rightQueue = queue(worker("y", "--threads", "1", "--queue", "team-a"));

        assertTrue(wrongQueue.stdout().contains("Scanned 0 job(s)"), wrongQueue.stdout());
        assertTrue(rightQueue.stdout().contains("Scanned 5 job(s)"), rightQueue.stdout());
    }

    @Test
    void emptyFileQueuesNothingAndNeverConnects() throws Exception {
        Path empty = tempDir.resolve("empty.txt");
        Files.writeString(empty, "# nothing here\n\n");

        Captured result = queue("produce", "--file", empty.toString(), "--redis-port", "1");

        assertEquals(0, result.exitCode(), result.stderr());
        assertTrue(result.stdout().contains("contains no URLs"));
    }

    @Test
    void unreachableRedisIsAClearError() throws Exception {
        int closedPort;
        try (ServerSocket socket = new ServerSocket(0)) {
            closedPort = socket.getLocalPort();
        }
        String port = Integer.toString(closedPort);

        Captured produce = queue("produce", "--file", urlFile(2).toString(), "--redis-host", "127.0.0.1", "--redis-port", port);
        Captured worker = queue("worker", "--redis-host", "127.0.0.1", "--redis-port", port, "--no-history", "--no-history-db");

        assertEquals(1, produce.exitCode());
        assertTrue(produce.stderr().contains("Error: can't reach Redis at 127.0.0.1:" + port), produce.stderr());
        assertTrue(produce.stderr().contains("docker run -d --name phishnet-redis -p 6379:6379 redis"));
        assertEquals(1, worker.exitCode());
        assertTrue(worker.stderr().contains("Add --retry to keep trying"), worker.stderr());
    }

    @Test
    void missingFileAndBadOptionsAreReported() {
        Captured missing = queue(at("produce", "--file", tempDir.resolve("nope.txt").toString()));
        assertEquals(1, missing.exitCode());
        assertTrue(missing.stderr().contains("file not found"), missing.stderr());

        assertEquals(2, queue("produce").exitCode(), "--file is required");
        assertEquals(2, queue(worker("z", "--threads", "0")).exitCode());
        assertEquals(2, queue("worker", "--redis-port", "70000").exitCode());
        assertEquals(2, queue().exitCode(), "a subcommand is required");
    }

    @Test
    void redisCredentialsComeFromTheEnvironmentAndAreNeverPrinted() throws Exception {
        env.put(QueueCommand.PASSWORD_ENV, "redis-s3cret");
        env.put(QueueCommand.USERNAME_ENV, "phishnet");

        Captured produced = queue(at("produce", "--file", urlFile(2).toString()));
        Captured worked = queue(worker("p", "--threads", "1", "--verbose"));

        assertEquals(0, produced.exitCode(), produced.stderr());
        assertEquals(0, worked.exitCode(), worked.stderr());
        assertFalse(connections.isEmpty());
        assertTrue(connections.stream().allMatch(s -> "redis-s3cret".equals(s.password())
                && "phishnet".equals(s.username())));
        String output = produced.stdout() + produced.stderr() + worked.stdout() + worked.stderr();
        assertFalse(output.contains("redis-s3cret"), output);
    }

    @Test
    void mainDispatchesTheQueueCommand() {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (PrintStream stream = new PrintStream(bytes, true, StandardCharsets.UTF_8)) {
            assertEquals(0, Main.run(new String[] {"queue", "--help"}, stream, stream, OFFLINE_WHOIS));
        }
        String help = bytes.toString(StandardCharsets.UTF_8);
        assertTrue(help.contains("produce"), help);
        assertTrue(help.contains("worker"), help);
        assertTrue(help.contains("PHISHNET_REDIS_PASSWORD"), help);
    }
}
