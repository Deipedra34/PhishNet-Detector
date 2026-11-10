package com.phishnet.feeds;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.net.URI;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Refreshing, fallback to cache, and graceful skipping, all against a fake fetcher and a fixed clock. */
class ThreatFeedServiceTest {

    private static final Instant NOW = Instant.parse("2026-11-10T12:00:00Z");
    private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);
    private static final String OPENPHISH_HOST = "openphish.com";
    private static final String PHISHTANK_HOST = "data.phishtank.com";
    private static final String OPENPHISH_FEED = "https://evil.example/login\nhttps://bad.example/pay\n";
    private static final String PHISHTANK_FEED = "[{\"phish_id\": 1, \"url\": \"https://tank.example/x\"}]";

    private static ThreatFeedSettings settings(Duration scanWait, String phishTankKey, String phishTankUser) {
        return new ThreatFeedSettings(Duration.ofHours(1), scanWait, Duration.ofSeconds(5), true,
                ThreatFeedSettings.DEFAULT_OPENPHISH_URL, ThreatFeedSettings.DEFAULT_USER_AGENT, Set.of(), true,
                phishTankKey, phishTankUser, ThreatFeedSettings.DEFAULT_PHISHTANK_URL);
    }

    private static ThreatFeedSettings openPhishOnly() {
        return settings(Duration.ofSeconds(5), null, null);
    }

    private static ThreatFeedService service(ThreatFeedSettings settings, Path dir, FakeFeedFetcher fetcher) {
        return new ThreatFeedService(settings, new FeedCache(dir), fetcher, CLOCK);
    }

    private static FeedStatus statusOf(List<FeedStatus> statuses, FeedSource source) {
        return statuses.stream().filter(s -> s.source() == source).findFirst().orElseThrow();
    }

    private static void cacheOpenPhish(Path dir, Instant refreshedAt, String... keys) throws IOException {
        new FeedCache(dir).write(FeedSource.OPENPHISH, FeedEntries.ofKeys(List.of(keys)), refreshedAt);
    }

    // --- refresh ---------------------------------------------------------------

    @Test
    void refreshDownloadsParsesAndCachesTheFeed(@TempDir Path dir) {
        FakeFeedFetcher fetcher = new FakeFeedFetcher().respond(OPENPHISH_HOST, OPENPHISH_FEED);
        ThreatFeedService service = service(openPhishOnly(), dir, fetcher);

        FeedRefreshResult result = service.refresh(FeedSource.OPENPHISH);

        assertEquals(FeedRefreshResult.Outcome.UPDATED, result.outcome());
        assertEquals(2, result.entries());
        FeedSnapshot cached = new FeedCache(dir).read(FeedSource.OPENPHISH).orElseThrow();
        assertEquals(NOW, cached.refreshedAt());
        assertTrue(cached.entries().containsUrl("evil.example/login"));
        FakeFeedFetcher.Call call = fetcher.calls().get(0);
        assertEquals(URI.create("https://openphish.com/feed.txt"), call.uri());
        assertEquals(ThreatFeedSettings.DEFAULT_USER_AGENT, call.headers().get("User-Agent"));
        assertEquals(Duration.ofSeconds(5), call.timeout());
    }

    @Test
    void failedRefreshKeepsThePreviousCopy(@TempDir Path dir) throws IOException {
        cacheOpenPhish(dir, NOW.minus(Duration.ofHours(3)), "old.example/x");
        FakeFeedFetcher fetcher = new FakeFeedFetcher().fail(OPENPHISH_HOST, "HTTP 503 from openphish.com");

        FeedRefreshResult result = service(openPhishOnly(), dir, fetcher).refresh(FeedSource.OPENPHISH);

        assertEquals(FeedRefreshResult.Outcome.FAILED, result.outcome());
        assertEquals("HTTP 503 from openphish.com", result.message());
        assertTrue(new FeedCache(dir).read(FeedSource.OPENPHISH).orElseThrow().entries().containsUrl("old.example/x"));
        assertEquals("HTTP 503 from openphish.com", new FeedCache(dir).metadata(FeedSource.OPENPHISH).lastError());
    }

    @Test
    void emptyDownloadIsAFailureNotAnEmptyFeed(@TempDir Path dir) throws IOException {
        cacheOpenPhish(dir, NOW.minus(Duration.ofHours(3)), "old.example/x");
        FakeFeedFetcher fetcher = new FakeFeedFetcher().respond(OPENPHISH_HOST, "# nothing here\n\n");

        FeedRefreshResult result = service(openPhishOnly(), dir, fetcher).refresh(FeedSource.OPENPHISH);

        assertEquals(FeedRefreshResult.Outcome.FAILED, result.outcome());
        assertEquals(1, new FeedCache(dir).read(FeedSource.OPENPHISH).orElseThrow().entries().size());
    }

    @Test
    void refreshAllCoversEveryFeed(@TempDir Path dir) {
        FakeFeedFetcher fetcher = new FakeFeedFetcher().respond(OPENPHISH_HOST, OPENPHISH_FEED);

        List<FeedRefreshResult> results = service(openPhishOnly(), dir, fetcher).refreshAll();

        assertEquals(List.of(FeedSource.OPENPHISH, FeedSource.PHISHTANK),
                results.stream().map(FeedRefreshResult::source).toList());
        assertEquals(FeedRefreshResult.Outcome.UPDATED, results.get(0).outcome());
        assertEquals(FeedRefreshResult.Outcome.SKIPPED, results.get(1).outcome());
    }

    // --- PhishTank: optional key -----------------------------------------------

    @Test
    void phishTankWithoutAKeyIsSkippedAndNeverDownloaded(@TempDir Path dir) {
        FakeFeedFetcher fetcher = new FakeFeedFetcher().respond(OPENPHISH_HOST, OPENPHISH_FEED);
        ThreatFeedService service = service(openPhishOnly(), dir, fetcher);

        FeedRefreshResult result = service.refresh(FeedSource.PHISHTANK);
        ThreatFeedIndex index = service.loadForScan();

        assertEquals(FeedRefreshResult.Outcome.SKIPPED, result.outcome());
        assertTrue(result.message().contains(ThreatFeedSettings.PHISHTANK_API_KEY_ENV), result.message());
        assertEquals(0, fetcher.callsTo(PHISHTANK_HOST));
        FeedStatus phishTank = statusOf(index.statuses(), FeedSource.PHISHTANK);
        assertEquals(FeedStatus.State.NOT_CONFIGURED, phishTank.state());
        assertFalse(phishTank.state().available());
        // OpenPhish carries on regardless.
        assertEquals(FeedStatus.State.FRESH, statusOf(index.statuses(), FeedSource.OPENPHISH).state());
        assertEquals(1, index.signalsFor("https://evil.example/login").size());
    }

    @Test
    void phishTankWithAKeyDownloadsFromTheKeyedUrl(@TempDir Path dir) {
        FakeFeedFetcher fetcher = new FakeFeedFetcher()
                .respond(OPENPHISH_HOST, OPENPHISH_FEED)
                .respond(PHISHTANK_HOST, PHISHTANK_FEED);
        ThreatFeedService service = service(settings(Duration.ofSeconds(5), "k3y/+=", "analyst"), dir, fetcher);

        FeedRefreshResult result = service.refresh(FeedSource.PHISHTANK);

        assertEquals(FeedRefreshResult.Outcome.UPDATED, result.outcome());
        FakeFeedFetcher.Call call = fetcher.calls().get(0);
        assertEquals("https://data.phishtank.com/data/k3y%2F%2B%3D/online-valid.json.gz", call.uri().toString());
        assertEquals("phishtank/analyst", call.headers().get("User-Agent"));
        assertEquals("Known phishing URL (PhishTank)",
                service.loadForScan().signalsFor("http://tank.example/x").get(0).description());
    }

    @Test
    void disabledFeedIsNeitherDownloadedNorMatched(@TempDir Path dir) throws IOException {
        cacheOpenPhish(dir, NOW, "evil.example/login");
        ThreatFeedSettings disabled = new ThreatFeedSettings(Duration.ofHours(1), Duration.ofSeconds(1),
                Duration.ofSeconds(5), false, ThreatFeedSettings.DEFAULT_OPENPHISH_URL,
                ThreatFeedSettings.DEFAULT_USER_AGENT, Set.of(), false, "key", null,
                ThreatFeedSettings.DEFAULT_PHISHTANK_URL);
        FakeFeedFetcher fetcher = new FakeFeedFetcher();

        ThreatFeedIndex index = service(disabled, dir, fetcher).loadForScan();

        assertTrue(index.isEmpty());
        assertTrue(fetcher.calls().isEmpty());
        assertEquals(FeedStatus.State.DISABLED, statusOf(index.statuses(), FeedSource.OPENPHISH).state());
        assertEquals(FeedStatus.State.DISABLED, statusOf(index.statuses(), FeedSource.PHISHTANK).state());
    }

    @Test
    void environmentKeyOverridesTheConfigFile() {
        ThreatFeedSettings fromConfig = settings(Duration.ofSeconds(1), "config-key", "config-user");

        ThreatFeedSettings resolved = fromConfig.withEnvironment(Map.of(
                ThreatFeedSettings.PHISHTANK_API_KEY_ENV, "  env-key  ",
                ThreatFeedSettings.PHISHTANK_USERNAME_ENV, "env-user"));

        assertEquals("env-key", resolved.phishTankApiKey());
        assertEquals("env-user", resolved.phishTankUsername());
        assertEquals("config-key", fromConfig.withEnvironment(Map.of(
                ThreatFeedSettings.PHISHTANK_API_KEY_ENV, "   ")).phishTankApiKey());
        assertNull(ThreatFeedSettings.defaults().withEnvironment(Map.of()).phishTankApiKey());
    }

    // --- loadForScan: fresh / stale / missing ------------------------------------

    @Test
    void freshCacheIsUsedWithoutDownloading(@TempDir Path dir) throws IOException {
        cacheOpenPhish(dir, NOW.minus(Duration.ofMinutes(10)), "evil.example/login");
        FakeFeedFetcher fetcher = new FakeFeedFetcher().fail(OPENPHISH_HOST, "must not be called");

        ThreatFeedIndex index = service(openPhishOnly(), dir, fetcher).loadForScan();

        assertEquals(0, fetcher.callsTo(OPENPHISH_HOST));
        FeedStatus status = statusOf(index.statuses(), FeedSource.OPENPHISH);
        assertEquals(FeedStatus.State.FRESH, status.state());
        assertEquals(1, status.entries());
        assertEquals(1, index.signalsFor("https://evil.example/login").size());
    }

    @Test
    void staleCacheIsRefreshedBeforeScanning(@TempDir Path dir) throws IOException {
        cacheOpenPhish(dir, NOW.minus(Duration.ofHours(2)), "old.example/x");
        FakeFeedFetcher fetcher = new FakeFeedFetcher().respond(OPENPHISH_HOST, OPENPHISH_FEED);

        ThreatFeedIndex index = service(openPhishOnly(), dir, fetcher).loadForScan();

        assertEquals(1, fetcher.callsTo(OPENPHISH_HOST));
        assertEquals(FeedStatus.State.FRESH, statusOf(index.statuses(), FeedSource.OPENPHISH).state());
        assertEquals(1, index.signalsFor("https://evil.example/login").size());
        assertTrue(index.signalsFor("https://old.example/x").isEmpty());
    }

    @Test
    void staleCacheIsStillUsedWhenTheRefreshFails(@TempDir Path dir) throws IOException {
        cacheOpenPhish(dir, NOW.minus(Duration.ofHours(2)), "evil.example/login");
        FakeFeedFetcher fetcher = new FakeFeedFetcher().fail(OPENPHISH_HOST, "connect timed out");

        ThreatFeedIndex index = service(openPhishOnly(), dir, fetcher).loadForScan();

        FeedStatus status = statusOf(index.statuses(), FeedSource.OPENPHISH);
        assertEquals(FeedStatus.State.STALE, status.state());
        assertTrue(status.state().available());
        assertTrue(status.detail().contains("connect timed out"), status.detail());
        assertEquals(1, index.signalsFor("https://evil.example/login").size());
    }

    @Test
    void missingFeedWithAFailedDownloadIsSkippedEntirely(@TempDir Path dir) {
        FakeFeedFetcher fetcher = new FakeFeedFetcher().fail(OPENPHISH_HOST, "no network");

        ThreatFeedIndex index = service(openPhishOnly(), dir, fetcher).loadForScan();

        assertTrue(index.isEmpty());
        FeedStatus status = statusOf(index.statuses(), FeedSource.OPENPHISH);
        assertEquals(FeedStatus.State.MISSING, status.state());
        assertFalse(status.state().available());
        assertTrue(index.signalsFor("https://evil.example/login").isEmpty());
    }

    @Test
    void slowDownloadNeverHoldsUpTheScan(@TempDir Path dir) throws Exception {
        CountDownLatch release = new CountDownLatch(1);
        FakeFeedFetcher fetcher = new FakeFeedFetcher().blockUntil(OPENPHISH_HOST, release, OPENPHISH_FEED);
        ThreatFeedService service = service(settings(Duration.ofMillis(200), null, null), dir, fetcher);

        try {
            long started = System.nanoTime();
            ThreatFeedIndex index = service.loadForScan();
            Duration took = Duration.ofNanos(System.nanoTime() - started);

            assertTrue(took.compareTo(Duration.ofSeconds(5)) < 0, "scan waited " + took);
            assertTrue(index.isEmpty());
            FeedStatus status = statusOf(index.statuses(), FeedSource.OPENPHISH);
            assertEquals(FeedStatus.State.MISSING, status.state());
            assertTrue(status.detail().contains("background"), status.detail());
        } finally {
            release.countDown();
        }

        // The download carries on in the background and lands in the cache for the next run.
        FeedCache cache = new FeedCache(dir);
        long deadline = System.nanoTime() + Duration.ofSeconds(10).toNanos();
        while (cache.read(FeedSource.OPENPHISH).isEmpty() && System.nanoTime() < deadline) {
            Thread.sleep(20);
        }
        assertTrue(cache.read(FeedSource.OPENPHISH).isPresent());
    }

    @Test
    void slowDownloadFallsBackToTheStaleCopy(@TempDir Path dir) throws Exception {
        cacheOpenPhish(dir, NOW.minus(Duration.ofHours(2)), "evil.example/login");
        CountDownLatch release = new CountDownLatch(1);
        FakeFeedFetcher fetcher = new FakeFeedFetcher().blockUntil(OPENPHISH_HOST, release, OPENPHISH_FEED);

        try {
            ThreatFeedIndex index = service(settings(Duration.ofMillis(100), null, null), dir, fetcher).loadForScan();

            assertEquals(FeedStatus.State.STALE, statusOf(index.statuses(), FeedSource.OPENPHISH).state());
            assertEquals(1, index.signalsFor("https://evil.example/login").size());
        } finally {
            release.countDown();
        }
        awaitAttempt(dir);
    }

    @Test
    void offlineServiceNeverDownloadsOrReadsTheCache() {
        ThreatFeedService service = ThreatFeedService.offline(ThreatFeedSettings.defaults());

        ThreatFeedIndex index = service.loadForScan();

        assertTrue(service.isOffline());
        assertTrue(index.isEmpty());
        assertTrue(index.statuses().stream().allMatch(s -> s.state() == FeedStatus.State.OFF));
        assertEquals(FeedRefreshResult.Outcome.SKIPPED, service.refresh(FeedSource.OPENPHISH).outcome());
    }

    // --- status ------------------------------------------------------------------

    @Test
    void statusReportsFreshStaleAndMissingFromTheCacheAlone(@TempDir Path dir) throws IOException {
        FakeFeedFetcher fetcher = new FakeFeedFetcher();
        ThreatFeedService service = service(settings(Duration.ofSeconds(1), "key", null), dir, fetcher);

        assertEquals(FeedStatus.State.MISSING, statusOf(service.status(), FeedSource.OPENPHISH).state());

        cacheOpenPhish(dir, NOW.minus(Duration.ofMinutes(5)), "a.example/", "b.example/");
        FeedStatus fresh = statusOf(service.status(), FeedSource.OPENPHISH);
        assertEquals(FeedStatus.State.FRESH, fresh.state());
        assertEquals(2, fresh.entries());
        assertEquals(NOW.minus(Duration.ofMinutes(5)), fresh.refreshedAt());

        cacheOpenPhish(dir, NOW.minus(Duration.ofHours(1)), "a.example/");
        assertEquals(FeedStatus.State.STALE, statusOf(service.status(), FeedSource.OPENPHISH).state());

        assertTrue(fetcher.calls().isEmpty());
    }

    /** Waits for a background refresh to record its attempt, so the temp dir isn't deleted under it. */
    private static void awaitAttempt(Path dir) throws InterruptedException {
        FeedCache cache = new FeedCache(dir);
        long deadline = System.nanoTime() + Duration.ofSeconds(10).toNanos();
        while (!NOW.equals(cache.metadata(FeedSource.OPENPHISH).lastAttempt()) && System.nanoTime() < deadline) {
            Thread.sleep(20);
        }
    }
}
