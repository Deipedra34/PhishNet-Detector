package com.phishnet.api;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.phishnet.analyzer.UrlAnalyzer;
import com.phishnet.feeds.FakeFeedFetcher;
import com.phishnet.feeds.FeedCache;
import com.phishnet.feeds.FeedEntries;
import com.phishnet.feeds.FeedSource;
import com.phishnet.feeds.ThreatFeedService;
import com.phishnet.feeds.ThreatFeedSettings;
import com.phishnet.history.HistoryDatabase;
import com.phishnet.history.HistoryStats;
import com.phishnet.model.DomainAgeResult;
import com.phishnet.model.PhishNetConfig;
import com.phishnet.model.RiskLevel;
import com.phishnet.model.RiskScore;
import com.phishnet.model.Signal;
import com.phishnet.model.SignalCategory;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The read-only endpoints behind the web dashboard ({@code /api/history},
 * {@code /api/history/stats}, {@code /api/feeds/status}) and the dashboard's static
 * file serving, over real HTTP. Every test uses its own history database and feed
 * cache under a temp directory, so nothing touches {@code ~/.phishnet}.
 */
class DashboardApiTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final UrlAnalyzer URLS = new UrlAnalyzer(PhishNetConfig.defaultConfig());
    private static final Instant START = Instant.parse("2026-10-01T12:00:00Z");

    @TempDir
    Path tempDir;

    private final HttpClient http = HttpClient.newHttpClient();
    private final ByteArrayOutputStream serverLog = new ByteArrayOutputStream();
    private SteppingClock clock;
    private HistoryDatabase history;
    private ApiServer server;

    private record Response(int status, String contentType, String text) {
        JsonNode json() throws IOException {
            return MAPPER.readTree(text);
        }
    }

    @BeforeEach
    void setUp() {
        clock = new SteppingClock(START);
        history = new HistoryDatabase(tempDir.resolve("history.db"), true, log(), clock);
    }

    @AfterEach
    void stopServer() {
        if (server != null) {
            server.stop();
        }
    }

    private PrintStream log() {
        return new PrintStream(serverLog, true, StandardCharsets.UTF_8);
    }

    private ApiServer newServer() {
        return new ApiServer(new ScanService(PhishNetConfig.defaultConfig(), null), log());
    }

    private void startWithHistory() {
        server = newServer().withHistory(readOnly()).start(0);
    }

    /** A second, read-only handle on the same file - what {@code phishnet serve} gives the API. */
    private HistoryDatabase readOnly() {
        return new HistoryDatabase(history.file(), false, log());
    }

    private Response get(String path) throws IOException, InterruptedException {
        HttpResponse<String> response = http.send(
                HttpRequest.newBuilder(URI.create("http://localhost:" + server.port() + path)).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        return new Response(response.statusCode(), response.headers().firstValue("Content-Type").orElse(""),
                response.body());
    }

    private JsonNode getJson(String path, int expectedStatus) throws IOException, InterruptedException {
        Response response = get(path);
        assertEquals(expectedStatus, response.status(), response.text());
        assertTrue(response.contentType().startsWith("application/json"), response.contentType());
        return response.json();
    }

    private static RiskScore score(RiskLevel level, String... signalIds) {
        int value = level == RiskLevel.HIGH ? 80 : level == RiskLevel.MEDIUM ? 45 : 5;
        List<Signal> signals = new ArrayList<>();
        for (String id : signalIds) {
            signals.add(new Signal(id, SignalCategory.URL, "description of " + id));
        }
        return new RiskScore(value, level, signals, "recommendation");
    }

    /** Records a URL scan one minute after the previous one, so the order is deterministic. */
    private void recordUrl(String url, RiskLevel level, String... signalIds) {
        history.recordUrl(url, URLS.analyze(url).components(), score(level, signalIds), DomainAgeResult.skipped());
        clock.advance(Duration.ofMinutes(1));
    }

    private void recordEmail(String file, String sender, String subject, RiskLevel level) {
        history.recordEmail(file, sender, subject, score(level));
        clock.advance(Duration.ofMinutes(1));
    }

    private static List<String> targets(JsonNode body) {
        List<String> targets = new ArrayList<>();
        body.get("scans").forEach(scan -> targets.add(scan.get("target").asText()));
        return targets;
    }

    /** 25 URL scans, https://site-00.example/ (oldest) to https://site-24.example/ (newest). */
    private void recordNumberedScans() {
        for (int i = 0; i < 25; i++) {
            recordUrl(String.format("https://site-%02d.example/", i), RiskLevel.LOW);
        }
    }

    // --- GET /api/history: listing ----------------------------------------------

    @Test
    void historyOnMissingDatabaseIsEmptyAndCreatesNothing() throws Exception {
        startWithHistory();

        JsonNode body = getJson("/api/history", 200);

        assertEquals(0, body.get("total").asLong());
        assertEquals(0, body.get("scans").size());
        assertFalse(Files.exists(history.file()), "a read must not create the database");
    }

    @Test
    void historyListsScansNewestFirstWithAllFields() throws Exception {
        recordUrl("http://192.168.1.1/login", RiskLevel.HIGH, "ipAddressHost", "loginKeyword");
        recordEmail("invoice.eml", "billing@paypa1.tk", "Your invoice", RiskLevel.MEDIUM);
        startWithHistory();

        JsonNode body = getJson("/api/history", 200);

        assertEquals(2, body.get("total").asLong());
        JsonNode email = body.get("scans").get(0);
        assertEquals("EMAIL", email.get("type").asText());
        assertEquals("invoice.eml", email.get("target").asText());
        assertEquals("paypa1.tk", email.get("domain").asText());
        assertEquals("Your invoice", email.get("subject").asText());
        assertEquals("MEDIUM", email.get("riskLevel").asText());
        assertEquals(45, email.get("riskScore").asInt());
        assertEquals("2026-10-01T12:01:00Z", email.get("timestamp").asText());

        JsonNode url = body.get("scans").get(1);
        assertEquals("URL", url.get("type").asText());
        assertEquals("192.168.1.1", url.get("domain").asText());
        assertTrue(url.get("subject").isNull());
        assertTrue(url.get("domainAgeDays").isNull());
        assertEquals(2, url.get("reasons").size());
        assertEquals("ipAddressHost", url.get("reasons").get(0).get("id").asText());
        assertEquals("description of ipAddressHost", url.get("reasons").get(0).get("description").asText());
    }

    // --- GET /api/history: pagination --------------------------------------------

    @Test
    void historyDefaultsToFirstPageOfTwenty() throws Exception {
        recordNumberedScans();
        startWithHistory();

        JsonNode body = getJson("/api/history", 200);

        assertEquals(25, body.get("total").asLong());
        assertEquals(HistoryApi.DEFAULT_LIMIT, body.get("limit").asInt());
        assertEquals(0, body.get("offset").asInt());
        List<String> targets = targets(body);
        assertEquals(20, targets.size());
        assertEquals("https://site-24.example/", targets.get(0));
        assertEquals("https://site-05.example/", targets.get(19));
    }

    @Test
    void historyPagesWithLimitAndOffset() throws Exception {
        recordNumberedScans();
        startWithHistory();

        JsonNode second = getJson("/api/history?limit=10&offset=10", 200);
        assertEquals(25, second.get("total").asLong());
        assertEquals(10, second.get("limit").asInt());
        assertEquals(10, second.get("offset").asInt());
        assertEquals("https://site-14.example/", targets(second).get(0));
        assertEquals("https://site-05.example/", targets(second).get(9));

        JsonNode last = getJson("/api/history?limit=10&offset=20", 200);
        assertEquals(List.of("https://site-04.example/", "https://site-03.example/", "https://site-02.example/",
                "https://site-01.example/", "https://site-00.example/"), targets(last));

        JsonNode beyond = getJson("/api/history?limit=10&offset=100", 200);
        assertEquals(25, beyond.get("total").asLong());
        assertEquals(0, beyond.get("scans").size());
    }

    @Test
    void historyRejectsInvalidPaging() throws Exception {
        startWithHistory();

        for (String query : List.of("limit=0", "limit=-1", "limit=" + (HistoryApi.MAX_LIMIT + 1), "limit=ten",
                "offset=-5", "offset=1.5")) {
            JsonNode body = getJson("/api/history?" + query, 400);
            assertTrue(body.get("error").asText().startsWith("Query parameter"), query + ": " + body);
        }
        assertEquals(HistoryApi.MAX_LIMIT,
                getJson("/api/history?limit=" + HistoryApi.MAX_LIMIT, 200).get("limit").asInt());
    }

    // --- GET /api/history: filtering ---------------------------------------------

    private void recordMixedScans() {
        recordUrl("https://paypal.com/signin", RiskLevel.LOW);
        recordUrl("http://paypa1-login.tk/verify", RiskLevel.HIGH, "typosquatting");
        recordUrl("https://bank.example/login", RiskLevel.MEDIUM, "loginKeyword");
        recordEmail("reset.eml", "security@paypa1.tk", "PayPal password reset", RiskLevel.HIGH);
        recordUrl("http://evil.tk/paypal", RiskLevel.HIGH, "suspiciousTld");
    }

    @Test
    void historyFiltersByTargetSubstringCaseInsensitively() throws Exception {
        recordMixedScans();
        startWithHistory();

        JsonNode body = getJson("/api/history?target=PAYPA", 200);

        // Matches the URL, the domain, or an email's subject - like `phishnet history search --target`.
        assertEquals(List.of("http://evil.tk/paypal", "reset.eml", "http://paypa1-login.tk/verify",
                "https://paypal.com/signin"), targets(body));
        assertEquals(4, body.get("total").asLong());
        JsonNode exact = getJson("/api/history?target=paypa1", 200);
        assertEquals(List.of("reset.eml", "http://paypa1-login.tk/verify"), targets(exact));
        assertEquals(2, exact.get("total").asLong());
    }

    @Test
    void historyTargetFilterTreatsWildcardsLiterally() throws Exception {
        recordUrl("https://example.com/50%_off", RiskLevel.MEDIUM);
        recordUrl("https://example.com/500-off", RiskLevel.LOW);
        startWithHistory();

        JsonNode body = getJson("/api/history?target=50%25_off", 200);

        assertEquals(List.of("https://example.com/50%_off"), targets(body));
    }

    @Test
    void historyFiltersByRiskLevelAndType() throws Exception {
        recordMixedScans();
        startWithHistory();

        JsonNode high = getJson("/api/history?risk=high", 200);
        assertEquals(3, high.get("total").asLong());
        high.get("scans").forEach(scan -> assertEquals("HIGH", scan.get("riskLevel").asText()));

        JsonNode highUrls = getJson("/api/history?risk=HIGH&type=url", 200);
        assertEquals(List.of("http://evil.tk/paypal", "http://paypa1-login.tk/verify"), targets(highUrls));

        JsonNode combined = getJson("/api/history?risk=HIGH&target=evil&limit=1", 200);
        assertEquals(1, combined.get("total").asLong());
        assertEquals(List.of("http://evil.tk/paypal"), targets(combined));
    }

    @Test
    void historyPaginatesWithinFilteredResults() throws Exception {
        recordMixedScans();
        startWithHistory();

        JsonNode page = getJson("/api/history?risk=HIGH&limit=2&offset=2", 200);

        assertEquals(3, page.get("total").asLong());
        assertEquals(List.of("http://paypa1-login.tk/verify"), targets(page));
    }

    @Test
    void historyRejectsUnknownRiskOrType() throws Exception {
        startWithHistory();

        assertTrue(getJson("/api/history?risk=CRITICAL", 400).get("error").asText().contains("LOW, MEDIUM, HIGH"));
        assertTrue(getJson("/api/history?type=sms", 400).get("error").asText().contains("URL, EMAIL"));
    }

    // --- GET /api/history/stats ----------------------------------------------------

    @Test
    void statsMatchTheHistoryStatsCommand() throws Exception {
        recordMixedScans();
        recordUrl("http://paypa1-login.tk/other", RiskLevel.MEDIUM);
        startWithHistory();

        JsonNode body = getJson("/api/history/stats", 200);

        assertEquals(6, body.get("total").asLong());
        assertEquals(1, body.get("byRiskLevel").get("LOW").asLong());
        assertEquals(2, body.get("byRiskLevel").get("MEDIUM").asLong());
        assertEquals(3, body.get("byRiskLevel").get("HIGH").asLong());
        assertEquals(5, body.get("byType").get("URL").asLong());
        assertEquals(1, body.get("byType").get("EMAIL").asLong());
        assertEquals("2026-10-01T12:00:00Z", body.get("firstScan").asText());
        assertEquals("2026-10-01T12:05:00Z", body.get("lastScan").asText());

        // paypa1-login.tk has two flagged URL scans; paypa1.tk (the email sender) and the
        // others one each, ties broken alphabetically. paypal.com was only ever LOW.
        JsonNode top = body.get("topFlaggedDomains");
        assertEquals("paypa1-login.tk", top.get(0).get("domain").asText());
        assertEquals(2, top.get(0).get("count").asLong());
        List<String> domains = new ArrayList<>();
        top.forEach(item -> domains.add(item.get("domain").asText()));
        assertFalse(domains.contains("paypal.com"), domains.toString());

        // Same figures as the query `phishnet history stats` runs.
        HistoryStats expected = readOnly().stats(HistoryApi.DEFAULT_TOP_DOMAINS);
        assertEquals(expected.total(), body.get("total").asLong());
        assertEquals(expected.topFlaggedDomains().size(), top.size());
        for (int i = 0; i < top.size(); i++) {
            assertEquals(expected.topFlaggedDomains().get(i).domain(), top.get(i).get("domain").asText());
            assertEquals(expected.topFlaggedDomains().get(i).count(), top.get(i).get("count").asLong());
        }
    }

    @Test
    void statsHonorTopAndValidateIt() throws Exception {
        recordMixedScans();
        startWithHistory();

        assertEquals(1, getJson("/api/history/stats?top=1", 200).get("topFlaggedDomains").size());
        assertEquals(0, getJson("/api/history/stats?top=0", 200).get("topFlaggedDomains").size());
        getJson("/api/history/stats?top=-1", 400);
        getJson("/api/history/stats?top=lots", 400);
    }

    @Test
    void statsOnEmptyHistoryAreAllZero() throws Exception {
        startWithHistory();

        JsonNode body = getJson("/api/history/stats", 200);

        assertEquals(0, body.get("total").asLong());
        assertEquals(0, body.get("byRiskLevel").get("HIGH").asLong());
        assertEquals(0, body.get("byType").get("EMAIL").asLong());
        assertTrue(body.get("firstScan").isNull());
        assertTrue(body.get("lastScan").isNull());
        assertEquals(0, body.get("topFlaggedDomains").size());
    }

    @Test
    void historyEndpointsAreUnavailableWithoutADatabase() throws Exception {
        server = newServer().start(0);

        assertTrue(getJson("/api/history", 503).get("error").asText().contains("not available"));
        getJson("/api/history/stats", 503);
    }

    @Test
    void historyEndpointsAreReadOnly() throws Exception {
        startWithHistory();

        HttpResponse<String> response = http.send(HttpRequest.newBuilder(
                        URI.create("http://localhost:" + server.port() + "/api/history"))
                .POST(HttpRequest.BodyPublishers.ofString("{}")).build(), HttpResponse.BodyHandlers.ofString());

        assertEquals(405, response.statusCode());
    }

    // --- GET /api/feeds/status ----------------------------------------------------------

    private static final Instant FEEDS_NOW = Instant.parse("2026-11-10T12:00:00Z");

    private ThreatFeedService feedService(Path cacheDir, String phishTankKey) {
        ThreatFeedSettings settings = new ThreatFeedSettings(Duration.ofHours(1), Duration.ofSeconds(5),
                Duration.ofSeconds(5), true, ThreatFeedSettings.DEFAULT_OPENPHISH_URL,
                ThreatFeedSettings.DEFAULT_USER_AGENT, Set.of(), true, phishTankKey, null,
                ThreatFeedSettings.DEFAULT_PHISHTANK_URL);
        return new ThreatFeedService(settings, new FeedCache(cacheDir), new FakeFeedFetcher(),
                Clock.fixed(FEEDS_NOW, ZoneOffset.UTC));
    }

    private static JsonNode feed(JsonNode body, String source) {
        for (JsonNode feed : body.get("feeds")) {
            if (feed.get("source").asText().equals(source)) {
                return feed;
            }
        }
        throw new AssertionError("no " + source + " feed in " + body);
    }

    @Test
    void feedStatusReportsCacheFreshnessAndEntries() throws Exception {
        Path cacheDir = tempDir.resolve("feeds");
        FeedCache cache = new FeedCache(cacheDir);
        cache.write(FeedSource.OPENPHISH, FeedEntries.ofKeys(List.of("evil.example/login", "bad.example/pay",
                "worse.example/x")), FEEDS_NOW.minus(Duration.ofMinutes(20)));
        cache.write(FeedSource.PHISHTANK, FeedEntries.ofKeys(List.of("tank.example/x")),
                FEEDS_NOW.minus(Duration.ofHours(3)));
        ThreatFeedService service = feedService(cacheDir, "test-key");
        server = newServer().withFeeds(service).start(0);

        JsonNode body = getJson("/api/feeds/status", 200);

        assertEquals(cacheDir.toString(), body.get("cacheDirectory").asText());
        assertEquals(3600, body.get("refreshIntervalSeconds").asLong());
        assertFalse(body.get("offline").asBoolean());

        JsonNode openPhish = feed(body, "openphish");
        assertEquals("OpenPhish", openPhish.get("name").asText());
        assertEquals("FRESH", openPhish.get("state").asText());
        assertTrue(openPhish.get("available").asBoolean());
        assertEquals(3, openPhish.get("entries").asInt());
        assertEquals(1200, openPhish.get("ageSeconds").asLong());
        assertEquals("2026-11-10T11:40:00Z", openPhish.get("refreshedAt").asText());

        JsonNode phishTank = feed(body, "phishtank");
        assertEquals("STALE", phishTank.get("state").asText());
        assertTrue(phishTank.get("available").asBoolean());
        assertEquals(1, phishTank.get("entries").asInt());

        // Exactly what `phishnet feeds status` is built on - and nothing was downloaded.
        assertEquals(service.status().size(), body.get("feeds").size());
    }

    @Test
    void feedStatusReportsMissingAndNotConfiguredFeeds() throws Exception {
        server = newServer().withFeeds(feedService(tempDir.resolve("empty-cache"), null)).start(0);

        JsonNode body = getJson("/api/feeds/status", 200);

        JsonNode openPhish = feed(body, "openphish");
        assertEquals("MISSING", openPhish.get("state").asText());
        assertFalse(openPhish.get("available").asBoolean());
        assertEquals(0, openPhish.get("entries").asInt());
        assertTrue(openPhish.get("refreshedAt").isNull());
        assertTrue(openPhish.get("ageSeconds").isNull());

        JsonNode phishTank = feed(body, "phishtank");
        assertEquals("NOT_CONFIGURED", phishTank.get("state").asText());
        assertTrue(phishTank.get("detail").asText().contains(ThreatFeedSettings.PHISHTANK_API_KEY_ENV));
        assertFalse(Files.exists(tempDir.resolve("empty-cache")), "a status read must not create the cache");
    }

    @Test
    void feedStatusOfAnOfflineServiceIsOff() throws Exception {
        server = newServer().withFeeds(ThreatFeedService.offline(feedService(tempDir, null).settings())).start(0);

        JsonNode body = getJson("/api/feeds/status", 200);

        assertTrue(body.get("offline").asBoolean());
        body.get("feeds").forEach(feed -> assertEquals("OFF", feed.get("state").asText()));
    }

    @Test
    void feedStatusIsUnavailableWithoutAFeedService() throws Exception {
        server = newServer().start(0);

        getJson("/api/feeds/status", 503);
    }

    // --- dashboard static files ------------------------------------------------------------

    private Path builtDashboard() throws IOException {
        Path dist = tempDir.resolve("dist");
        Files.createDirectories(dist.resolve("assets"));
        Files.writeString(dist.resolve("index.html"), "<!doctype html><title>PhishNet Dashboard</title>");
        Files.writeString(dist.resolve("assets").resolve("index-abc123.js"), "console.log('dashboard');");
        return dist;
    }

    @Test
    void dashboardIsServedAlongsideTheApi() throws Exception {
        server = newServer().withHistory(readOnly()).withDashboard(builtDashboard()).start(0);

        Response index = get("/");
        assertEquals(200, index.status());
        assertTrue(index.contentType().startsWith("text/html"), index.contentType());
        assertTrue(index.text().contains("PhishNet Dashboard"));

        Response asset = get("/assets/index-abc123.js");
        assertEquals(200, asset.status());
        assertTrue(asset.text().contains("dashboard"));

        // Client-side routes reload into the app.
        for (String route : List.of("/history", "/stats", "/feeds", "/history?risk=HIGH")) {
            Response page = get(route);
            assertEquals(200, page.status(), route);
            assertTrue(page.text().contains("PhishNet Dashboard"), route);
        }

        // The API is unchanged next to it.
        assertEquals("ok", getJson("/api/health", 200).get("status").asText());
        assertEquals(0, getJson("/api/history", 200).get("total").asLong());
    }

    @Test
    void dashboardFallbackKeepsApiErrorsAndMissingFilesAsJson() throws Exception {
        server = newServer().withDashboard(builtDashboard()).start(0);

        assertTrue(getJson("/api/does-not-exist", 404).get("error").asText().contains("not found"));
        assertTrue(getJson("/api/scan/url", 405).has("error"));
        getJson("/assets/index-old999.js", 404);
    }

    @Test
    void withoutADashboardTheRootIsAJson404() throws Exception {
        server = newServer().start(0);

        getJson("/", 404);
        getJson("/history", 404);
    }

    @Test
    void dashboardDirectoryMustContainAnIndex() {
        Path empty = tempDir.resolve("not-built");

        assertFalse(ApiServer.isDashboardDirectory(empty));
        assertThrows(IllegalArgumentException.class, () -> newServer().withDashboard(empty));
    }

    @Test
    void componentsCannotBeAddedAfterStart() {
        server = newServer().start(0);

        assertThrows(IllegalStateException.class, () -> server.withHistory(readOnly()));
        assertThrows(IllegalStateException.class, () -> server.start(0));
    }

    /** A clock the test moves forward by hand, so scans get distinct, ordered timestamps. */
    private static final class SteppingClock extends Clock {
        private Instant now;

        SteppingClock(Instant start) {
            this.now = start;
        }

        void advance(Duration duration) {
            now = now.plus(duration);
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }
}
