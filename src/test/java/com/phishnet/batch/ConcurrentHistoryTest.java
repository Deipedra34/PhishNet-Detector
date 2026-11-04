package com.phishnet.batch;

import com.phishnet.analyzer.DomainAgeChecker;
import com.phishnet.analyzer.WhoisClient;
import com.phishnet.cli.HistoryWriter;
import com.phishnet.history.HistoryDatabase;
import com.phishnet.history.HistoryEntry;
import com.phishnet.history.HistoryFilter;
import com.phishnet.model.DomainAgeResult;
import com.phishnet.model.RiskLevel;
import com.phishnet.model.RiskScore;
import com.phishnet.model.Signal;
import com.phishnet.model.SignalCategory;
import com.phishnet.model.UrlComponents;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The shared pieces of a parallel scan under real concurrency: N threads hammering the
 * CSV writer, the SQLite database, and the WHOIS cache at the same time.
 */
class ConcurrentHistoryTest {

    private static final int THREADS = 8;
    private static final int PER_THREAD = 50;

    private static final RiskScore SCORE = new RiskScore(70, RiskLevel.HIGH,
            List.of(new Signal("suspiciousTld", SignalCategory.URL, "bad TLD")), "Report and delete.");

    private final ByteArrayOutputStream errBytes = new ByteArrayOutputStream();
    private final PrintStream err = new PrintStream(errBytes, true, StandardCharsets.UTF_8);

    /** Runs {@code task(thread, i)} THREADS x PER_THREAD times, all threads released at once. */
    private static void hammer(TaskBody task) throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(THREADS);
        CountDownLatch start = new CountDownLatch(1);
        try {
            List<Future<?>> futures = new java.util.ArrayList<>();
            for (int t = 0; t < THREADS; t++) {
                int thread = t;
                futures.add(pool.submit(() -> {
                    start.await();
                    for (int i = 0; i < PER_THREAD; i++) {
                        task.run(thread, i);
                    }
                    return null;
                }));
            }
            start.countDown();
            for (Future<?> future : futures) {
                future.get(60, TimeUnit.SECONDS);
            }
        } finally {
            pool.shutdownNow();
        }
    }

    @FunctionalInterface
    private interface TaskBody {
        void run(int thread, int i) throws Exception;
    }

    private static UrlComponents components(String url) {
        return new UrlComponents(url, "http", "example.tk", -1, "", "example", "tk", "/", "",
                new LinkedHashMap<>(), false);
    }

    @Test
    void csvWriterSharedByManyThreadsLosesNoRows(@TempDir Path dir) throws Exception {
        Path csv = dir.resolve("history.csv");
        HistoryWriter writer = new HistoryWriter(csv, true, err);

        hammer((thread, i) -> writer.record("http://t" + thread + "-" + i + ".tk/", HistoryWriter.TargetType.URL,
                SCORE, DomainAgeResult.skipped()));

        assertCsvComplete(csv);
    }

    @Test
    void separateCsvWritersOnTheSameFileNeitherCollideNorDuplicateTheHeader(@TempDir Path dir) throws Exception {
        // Like several worker processes appending to one file: a writer per thread.
        Path csv = dir.resolve("history.csv");

        hammer((thread, i) -> new HistoryWriter(csv, true, err).record("http://t" + thread + "-" + i + ".tk/",
                HistoryWriter.TargetType.URL, SCORE, DomainAgeResult.skipped()));

        assertCsvComplete(csv);
    }

    private void assertCsvComplete(Path csv) throws IOException {
        List<String> lines = Files.readAllLines(csv, StandardCharsets.UTF_8);
        assertEquals("", errBytes.toString(StandardCharsets.UTF_8), "no write failures");
        assertEquals(1 + THREADS * PER_THREAD, lines.size());
        assertTrue(lines.get(0).startsWith("timestamp,target,"));
        Set<String> targets = new HashSet<>();
        for (String line : lines.subList(1, lines.size())) {
            String[] columns = line.split(",", -1);
            assertEquals(7, columns.length, "a torn or merged row: " + line);
            assertTrue(targets.add(columns[1]), "duplicate row: " + line);
            assertEquals("HIGH", columns[4]);
        }
        assertEquals(THREADS * PER_THREAD, targets.size());
    }

    @Test
    void historyDatabaseSharedByManyThreadsRecordsEveryScanOnce(@TempDir Path dir) throws Exception {
        HistoryDatabase database = new HistoryDatabase(dir.resolve("history.db"), true, err);

        hammer((thread, i) -> {
            String url = "http://t" + thread + "-" + i + ".tk/";
            database.recordUrl(url, components(url), SCORE, DomainAgeResult.skipped());
        });

        List<HistoryEntry> entries = database.search(HistoryFilter.recent(0));
        assertEquals("", errBytes.toString(StandardCharsets.UTF_8));
        assertEquals(THREADS * PER_THREAD, entries.size());
        assertEquals(THREADS * PER_THREAD, entries.stream().map(HistoryEntry::target).distinct().count());
    }

    @Test
    void concurrentChecksOfOneDomainShareASingleWhoisLookup() throws Exception {
        AtomicInteger queries = new AtomicInteger();
        CountDownLatch release = new CountDownLatch(1);
        WhoisClient slowRegistry = (server, query, timeout) -> {
            queries.incrementAndGet();
            try {
                release.await(10, TimeUnit.SECONDS); // keep the first lookup in flight while others arrive
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            return "Creation Date: 2001-02-03T00:00:00Z";
        };
        DomainAgeChecker checker = new DomainAgeChecker(slowRegistry);
        Set<DomainAgeResult> results = ConcurrentHashMap.newKeySet();

        ExecutorService pool = Executors.newFixedThreadPool(THREADS);
        try {
            List<Future<?>> futures = new java.util.ArrayList<>();
            for (int t = 0; t < THREADS; t++) {
                futures.add(pool.submit(() -> results.add(checker.check("example.com"))));
            }
            Thread.sleep(200);
            release.countDown();
            for (Future<?> future : futures) {
                future.get(10, TimeUnit.SECONDS);
            }
        } finally {
            pool.shutdownNow();
        }

        assertEquals(1, queries.get(), "one WHOIS query for one domain, however many threads ask");
        assertEquals(1, results.size(), "every caller gets the same result");
        assertTrue(results.iterator().next().isKnown());
    }

    @Test
    void differentDomainsAreLookedUpInParallel() throws Exception {
        CountDownLatch bothInFlight = new CountDownLatch(2);
        WhoisClient registry = (server, query, timeout) -> {
            bothInFlight.countDown();
            try {
                // Succeeds only if the two lookups overlap in time.
                return bothInFlight.await(10, TimeUnit.SECONDS) ? "Creation Date: 2001-02-03" : "";
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return "";
            }
        };
        DomainAgeChecker checker = new DomainAgeChecker(registry);
        ExecutorService pool = Executors.newFixedThreadPool(2);
        try {
            Future<DomainAgeResult> a = pool.submit(() -> checker.check("alpha.com"));
            Future<DomainAgeResult> b = pool.submit(() -> checker.check("beta.com"));
            assertTrue(a.get(15, TimeUnit.SECONDS).isKnown());
            assertTrue(b.get(15, TimeUnit.SECONDS).isKnown());
        } finally {
            pool.shutdownNow();
        }
    }
}
