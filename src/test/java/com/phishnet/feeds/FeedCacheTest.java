package com.phishnet.feeds;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The on-disk cache, and how fresh/stale/missing is decided from it. */
class FeedCacheTest {

    private static final Instant NOW = Instant.parse("2026-11-10T12:00:00Z");
    private static final Duration HOUR = Duration.ofHours(1);

    @Test
    void neverDownloadedFeedIsMissing() {
        assertEquals(FeedFreshness.MISSING, FeedFreshness.of(null, HOUR, NOW));
    }

    @Test
    void feedRefreshedWithinTheIntervalIsFresh() {
        assertEquals(FeedFreshness.FRESH, FeedFreshness.of(NOW.minusSeconds(59 * 60), HOUR, NOW));
        assertEquals(FeedFreshness.FRESH, FeedFreshness.of(NOW, HOUR, NOW));
    }

    @Test
    void feedAtOrPastTheIntervalIsStale() {
        assertEquals(FeedFreshness.STALE, FeedFreshness.of(NOW.minus(HOUR), HOUR, NOW));
        assertEquals(FeedFreshness.STALE, FeedFreshness.of(NOW.minus(Duration.ofDays(3)), HOUR, NOW));
    }

    @Test
    void refreshTimestampInTheFutureCountsAsFresh() {
        assertEquals(FeedFreshness.FRESH, FeedFreshness.of(NOW.plusSeconds(600), HOUR, NOW));
    }

    @Test
    void emptyDirectoryHasNoCachedFeeds(@TempDir Path dir) {
        FeedCache cache = new FeedCache(dir.resolve("feeds"));

        assertTrue(cache.read(FeedSource.OPENPHISH).isEmpty());
        assertEquals(FeedCache.Metadata.NONE, cache.metadata(FeedSource.OPENPHISH));
    }

    @Test
    void writtenFeedReadsBackWithItsRefreshTime(@TempDir Path dir) throws IOException {
        FeedCache cache = new FeedCache(dir.resolve("nested").resolve("feeds"));
        FeedEntries entries = FeedEntries.ofKeys(List.of("a.example/login", "b.example:8080/x?y=1"));

        cache.write(FeedSource.OPENPHISH, entries, NOW);

        FeedSnapshot snapshot = cache.read(FeedSource.OPENPHISH).orElseThrow();
        assertEquals(NOW, snapshot.refreshedAt());
        assertEquals(entries.urls(), snapshot.entries().urls());
        assertTrue(snapshot.entries().containsHost("b.example"));
        FeedCache.Metadata metadata = cache.metadata(FeedSource.OPENPHISH);
        assertEquals(2, metadata.entries());
        assertNull(metadata.lastError());
        // Each feed has its own files.
        assertTrue(cache.read(FeedSource.PHISHTANK).isEmpty());
    }

    @Test
    void failedRefreshKeepsTheCachedEntriesAndRecordsTheError(@TempDir Path dir) throws IOException {
        FeedCache cache = new FeedCache(dir);
        cache.write(FeedSource.OPENPHISH, FeedEntries.ofKeys(List.of("a.example/x")), NOW.minus(Duration.ofHours(5)));

        cache.recordFailure(FeedSource.OPENPHISH, "HTTP 503 from openphish.com", NOW);

        FeedSnapshot snapshot = cache.read(FeedSource.OPENPHISH).orElseThrow();
        assertEquals(NOW.minus(Duration.ofHours(5)), snapshot.refreshedAt());
        assertTrue(snapshot.entries().containsUrl("a.example/x"));
        FeedCache.Metadata metadata = cache.metadata(FeedSource.OPENPHISH);
        assertEquals("HTTP 503 from openphish.com", metadata.lastError());
        assertEquals(NOW, metadata.lastAttempt());
    }

    @Test
    void failureWithNothingCachedLeavesTheFeedMissing(@TempDir Path dir) {
        FeedCache cache = new FeedCache(dir);

        cache.recordFailure(FeedSource.OPENPHISH, "timed out", NOW);

        assertTrue(cache.read(FeedSource.OPENPHISH).isEmpty());
        assertNull(cache.metadata(FeedSource.OPENPHISH).refreshedAt());
        assertEquals("timed out", cache.metadata(FeedSource.OPENPHISH).lastError());
    }

    @Test
    void successfulRefreshClearsAnEarlierError(@TempDir Path dir) throws IOException {
        FeedCache cache = new FeedCache(dir);
        cache.recordFailure(FeedSource.OPENPHISH, "timed out", NOW.minusSeconds(60));

        cache.write(FeedSource.OPENPHISH, FeedEntries.ofKeys(List.of("a.example/")), NOW);

        assertNull(cache.metadata(FeedSource.OPENPHISH).lastError());
    }

    @Test
    void dataFileWithoutMetadataIsNotTrusted(@TempDir Path dir) throws IOException {
        Files.writeString(dir.resolve("openphish.txt"), "a.example/x\n", StandardCharsets.UTF_8);

        assertEquals(Optional.empty(), new FeedCache(dir).read(FeedSource.OPENPHISH));
    }

    @Test
    void corruptMetadataReadsAsNoCache(@TempDir Path dir) throws IOException {
        Files.writeString(dir.resolve("openphish.txt"), "a.example/x\n", StandardCharsets.UTF_8);
        Files.writeString(dir.resolve("openphish.properties"), "refreshedAt=not-a-time\nentries=lots\n",
                StandardCharsets.UTF_8);

        FeedCache cache = new FeedCache(dir);

        assertTrue(cache.read(FeedSource.OPENPHISH).isEmpty());
        assertEquals(0, cache.metadata(FeedSource.OPENPHISH).entries());
    }

    @Test
    void writesLeaveNoTemporaryFilesBehind(@TempDir Path dir) throws IOException {
        FeedCache cache = new FeedCache(dir);
        cache.write(FeedSource.OPENPHISH, FeedEntries.ofKeys(List.of("a.example/")), NOW);
        cache.recordFailure(FeedSource.OPENPHISH, "later failure", NOW.plusSeconds(1));

        try (var files = Files.list(dir)) {
            assertEquals(List.of("openphish.properties", "openphish.txt"),
                    files.map(p -> p.getFileName().toString()).sorted().toList());
        }
    }
}
