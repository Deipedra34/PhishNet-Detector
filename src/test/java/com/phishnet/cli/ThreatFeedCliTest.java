package com.phishnet.cli;

import com.phishnet.analyzer.WhoisClient;
import com.phishnet.feeds.FakeFeedFetcher;
import com.phishnet.feeds.FeedCache;
import com.phishnet.feeds.FeedEntries;
import com.phishnet.feeds.FeedSource;
import com.phishnet.feeds.ThreatFeedService;
import com.phishnet.feeds.ThreatFeedSettings;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.function.Function;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Threat feeds through the real CLI: scans, {@code --no-threat-feeds}, and the
 * {@code feeds} subcommands, with canned feeds served from a fake fetcher into a
 * temporary cache directory. Nothing here touches the network or {@code ~/.phishnet}.
 */
class ThreatFeedCliTest {

    private static final Instant NOW = Instant.parse("2026-11-10T12:00:00Z");
    private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);
    private static final String LISTED = "https://listed-site.example/account/login";
    private static final String OPENPHISH_FEED = LISTED + "\nhttps://other-phish.example/pay\n";

    private static final WhoisClient OFFLINE_WHOIS = (server, query, timeoutMillis) -> {
        throw new IOException("network disabled in tests");
    };

    private record Captured(int exitCode, String stdout, String stderr) {
    }

    @TempDir
    Path tempDir;

    private Path cacheDir;
    private FakeFeedFetcher fetcher;

    @BeforeEach
    void setUp() {
        cacheDir = tempDir.resolve("feeds");
        // PhishTank answers too, in case the machine running the tests has a real key in its environment.
        fetcher = new FakeFeedFetcher()
                .respond("openphish.com", OPENPHISH_FEED)
                .respond("data.phishtank.com", "[{\"url\": \"https://tank-only.example/x\"}]");
    }

    private Function<ThreatFeedSettings, ThreatFeedService> services() {
        return settings -> new ThreatFeedService(settings, new FeedCache(cacheDir), fetcher, CLOCK);
    }

    /** Runs a scan with every other side effect (WHOIS, history, ML) switched off. */
    private Captured scan(String... args) {
        List<String> all = new ArrayList<>(Arrays.asList(args));
        all.addAll(List.of("--no-whois", "--no-history", "--no-history-db", "--no-ml", "--no-color"));
        return run(all.toArray(String[]::new));
    }

    private Captured run(String... args) {
        ByteArrayOutputStream outBytes = new ByteArrayOutputStream();
        ByteArrayOutputStream errBytes = new ByteArrayOutputStream();
        try (PrintStream out = new PrintStream(outBytes, true, StandardCharsets.UTF_8);
             PrintStream err = new PrintStream(errBytes, true, StandardCharsets.UTF_8)) {
            int code = Main.run(args, out, err, OFFLINE_WHOIS, services());
            return new Captured(code, outBytes.toString(StandardCharsets.UTF_8),
                    errBytes.toString(StandardCharsets.UTF_8));
        }
    }

    // --- scans -----------------------------------------------------------------

    @Test
    void listedUrlIsFlaggedInNormalOutput() {
        Captured result = scan("--url", LISTED);

        assertEquals(0, result.exitCode(), result.stderr());
        assertTrue(result.stdout().contains("[knownPhishingUrl] Known phishing URL (OpenPhish)"), result.stdout());
        assertTrue(result.stdout().contains("(HIGH)"), result.stdout());
        // Evidence and the feed status block are VERBOSE-only.
        assertFalse(result.stdout().contains("listed in OpenPhish"), result.stdout());
        assertFalse(result.stdout().contains("Threat Feeds:"), result.stdout());
    }

    @Test
    void verboseOutputShowsTheMatchedEntryAndFeedStatus() {
        Captured result = scan("--url", LISTED, "--verbose");

        assertTrue(result.stdout().contains("listed-site.example/account/login listed in OpenPhish, feed refreshed "
                + NOW), result.stdout());
        assertTrue(result.stdout().contains("Threat Feeds:"), result.stdout());
        assertTrue(result.stdout().contains("  OpenPhish: fresh, 2 entries, refreshed " + NOW), result.stdout());
    }

    @Test
    void quietOutputReflectsTheFeedMatchInItsExitCode() {
        Captured result = scan("--url", LISTED, "--quiet");

        assertEquals(1, result.exitCode());
        assertTrue(result.stdout().startsWith("HIGH "), result.stdout());
    }

    @Test
    void jsonOutputIncludesTheFeedSignal() {
        Captured result = scan("--url", LISTED, "--json");

        assertTrue(result.stdout().contains("knownPhishingUrl"), result.stdout());
        assertTrue(result.stdout().contains("Known phishing URL (OpenPhish)"), result.stdout());
    }

    @Test
    void otherPageOnAListedHostIsAKnownPhishingDomain() {
        Captured result = scan("--url", "https://listed-site.example/");

        assertTrue(result.stdout().contains("[knownPhishingDomain] Known phishing domain (OpenPhish)"),
                result.stdout());
    }

    @Test
    void unlistedUrlGetsNoFeedSignal() {
        Captured result = scan("--url", "https://example.com/");

        assertFalse(result.stdout().contains("knownPhishing"), result.stdout());
    }

    @Test
    void noThreatFeedsFlagSkipsFeedsEntirely() {
        Captured result = scan("--url", LISTED, "--no-threat-feeds", "--verbose");

        assertEquals(0, result.exitCode());
        assertFalse(result.stdout().contains("knownPhishing"), result.stdout());
        assertFalse(result.stdout().contains("Threat Feeds:"), result.stdout());
        assertTrue(fetcher.calls().isEmpty());
        assertFalse(Files.exists(cacheDir));
    }

    @Test
    void feedFlagLeavesTheRestOfTheScoreAlone() {
        Captured withFeeds = scan("--url", "http://paypa1-login.xyz/verify", "--quiet");
        Captured withoutFeeds = scan("--url", "http://paypa1-login.xyz/verify", "--quiet", "--no-threat-feeds");

        assertEquals(withoutFeeds.stdout(), withFeeds.stdout());
    }

    @Test
    void scanStillWorksWhenFeedsAreUnreachableAndNothingIsCached() {
        fetcher = new FakeFeedFetcher();

        Captured result = scan("--url", LISTED, "--verbose");

        assertEquals(0, result.exitCode(), result.stderr());
        assertTrue(result.stdout().contains("Risk Score:"), result.stdout());
        assertFalse(result.stdout().contains("knownPhishing"), result.stdout());
        assertTrue(result.stdout().contains("OpenPhish: unavailable (no cached copy yet)"), result.stdout());
    }

    @Test
    void staleCacheIsUsedWhenTheFeedIsUnreachable() throws IOException {
        new FeedCache(cacheDir).write(FeedSource.OPENPHISH,
                FeedEntries.ofKeys(List.of("listed-site.example/account/login")), NOW.minus(Duration.ofDays(2)));
        fetcher = new FakeFeedFetcher();

        Captured result = scan("--url", LISTED, "--verbose");

        assertTrue(result.stdout().contains("[knownPhishingUrl] Known phishing URL (OpenPhish)"), result.stdout());
        assertTrue(result.stdout().contains("OpenPhish: stale, 1 entry"), result.stdout());
    }

    @Test
    void batchScanFlagsOnlyTheListedUrls() throws IOException {
        Path batch = tempDir.resolve("urls.txt");
        Files.writeString(batch, "https://example.com/\n" + LISTED + "\n", StandardCharsets.UTF_8);

        Captured result = scan("--batch", batch.toString(), "--threads", "2");

        assertEquals(1, result.stdout().split("knownPhishingUrl", -1).length - 1, result.stdout());
        assertTrue(result.stdout().contains("1 high risk"), result.stdout());
        // One download for the whole batch, not one per URL.
        assertEquals(1, fetcher.callsTo("openphish.com"));
    }

    @Test
    void emailWithAListedLinkIsFlagged() throws IOException {
        Path eml = tempDir.resolve("message.eml");
        Files.writeString(eml, "From: Alice <alice@example.com>\n"
                + "To: bob@example.com\n"
                + "Subject: Lunch\n"
                + "Content-Type: text/plain; charset=UTF-8\n\n"
                + "See you tomorrow. Also check " + LISTED + " please.\n", StandardCharsets.UTF_8);

        Captured result = scan("--email", eml.toString());

        assertTrue(result.stdout().contains("[knownPhishingUrl] Known phishing URL (OpenPhish)"), result.stdout());
    }

    // --- feeds update / status ---------------------------------------------------

    @Test
    void feedsUpdateDownloadsAndCachesEveryFeed() {
        Captured result = run("feeds", "update");

        assertEquals(0, result.exitCode(), result.stdout() + result.stderr());
        assertTrue(result.stdout().contains("OpenPhish:  updated, 2 entries"), result.stdout());
        assertTrue(result.stdout().contains("PhishTank:"), result.stdout());
        assertTrue(new FeedCache(cacheDir).read(FeedSource.OPENPHISH).isPresent());
    }

    @Test
    void feedsUpdateReportsFailuresWithExitCode1() {
        fetcher = new FakeFeedFetcher().fail("openphish.com", "HTTP 503 from openphish.com")
                .respond("data.phishtank.com", "[{\"url\": \"https://tank-only.example/x\"}]");

        Captured result = run("feeds", "update");

        assertEquals(1, result.exitCode());
        assertTrue(result.stdout().contains("OpenPhish:  FAILED: HTTP 503 from openphish.com"), result.stdout());
        assertTrue(result.stderr().contains("previous cached copy"), result.stderr());
    }

    @Test
    void feedsStatusShowsAMissingFeed() {
        Captured result = run("feeds", "status");

        assertEquals(0, result.exitCode(), result.stderr());
        assertTrue(result.stdout().contains("Cache directory:  " + cacheDir), result.stdout());
        assertTrue(result.stdout().contains("Refresh interval: 1 hour"), result.stdout());
        assertTrue(result.stdout().contains("Status:       missing"), result.stdout());
        assertTrue(result.stdout().contains("Last refresh: never"), result.stdout());
        assertTrue(fetcher.calls().isEmpty(), "status must never download");
    }

    @Test
    void feedsStatusShowsAFreshFeedAfterAnUpdate() {
        run("feeds", "update");

        Captured result = run("feeds", "status");

        assertTrue(result.stdout().contains("Status:       fresh (cached and available to scans)"), result.stdout());
        assertTrue(result.stdout().contains("Last refresh: " + NOW + " (0 seconds ago)"), result.stdout());
        assertTrue(result.stdout().contains("Entries:      2"), result.stdout());
    }

    @Test
    void feedsStatusShowsAStaleFeedAndTheLastError() throws IOException {
        FeedCache cache = new FeedCache(cacheDir);
        cache.write(FeedSource.OPENPHISH, FeedEntries.ofKeys(List.of("a.example/", "b.example/", "c.example/")),
                NOW.minus(Duration.ofHours(5)));
        cache.recordFailure(FeedSource.OPENPHISH, "connect timed out", NOW.minus(Duration.ofMinutes(1)));

        Captured result = run("feeds", "status");

        assertTrue(result.stdout().contains("Status:       stale"), result.stdout());
        assertTrue(result.stdout().contains("(5 hours ago)"), result.stdout());
        assertTrue(result.stdout().contains("Entries:      3"), result.stdout());
        assertTrue(result.stdout().contains("Last error:   connect timed out"), result.stdout());
    }

    @Test
    void feedsStatusHonorsACustomConfig() throws IOException {
        Path config = tempDir.resolve("config.yaml");
        Files.writeString(config, "threatFeeds:\n  refreshIntervalMinutes: 15\n  openPhish:\n    enabled: false\n",
                StandardCharsets.UTF_8);

        Captured result = run("feeds", "status", "--config", config.toString());

        assertTrue(result.stdout().contains("Refresh interval: 15 minutes"), result.stdout());
        assertTrue(result.stdout().contains("Status:       disabled in the config"), result.stdout());
    }

    @Test
    void feedsWithoutASubcommandIsAUsageError() {
        Captured result = run("feeds");

        assertEquals(2, result.exitCode());
        assertTrue(result.stderr().contains("Missing required command: update or status"), result.stderr());
    }

    @Test
    void durationsUseTheLargestWholeUnit() {
        assertEquals("1 second", FeedsCommand.formatDuration(Duration.ofSeconds(1)));
        assertEquals("59 seconds", FeedsCommand.formatDuration(Duration.ofSeconds(59)));
        assertEquals("1 minute", FeedsCommand.formatDuration(Duration.ofSeconds(90)));
        assertEquals("2 hours", FeedsCommand.formatDuration(Duration.ofMinutes(150)));
        assertEquals("3 days", FeedsCommand.formatDuration(Duration.ofDays(3)));
        assertEquals("0 seconds", FeedsCommand.formatDuration(Duration.ofSeconds(-5)));
    }
}
