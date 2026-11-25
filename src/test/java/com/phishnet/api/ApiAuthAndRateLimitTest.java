package com.phishnet.api;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.phishnet.feeds.FakeFeedFetcher;
import com.phishnet.feeds.FeedCache;
import com.phishnet.feeds.ThreatFeedService;
import com.phishnet.feeds.ThreatFeedSettings;
import com.phishnet.history.HistoryDatabase;
import com.phishnet.model.PhishNetConfig;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** API key checks and rate limiting over real HTTP, against an {@link ApiServer} on a free port. */
class ApiAuthAndRateLimitTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String KEY = "test-api-key-0123456789abcdef";
    private static final String SCAN_BODY = "{\"url\":\"http://paypa1.com/signin\"}";

    @TempDir
    Path tempDir;

    private final HttpClient http = HttpClient.newHttpClient();
    private final AtomicLong nanos = new AtomicLong(5_000_000_000L);
    private ApiServer server;

    private record Response(int status, JsonNode body, HttpResponse<String> raw) {
        String header(String name) {
            return raw.headers().firstValue(name).orElse(null);
        }
    }

    @AfterEach
    void stopServer() {
        if (server != null) {
            server.stop();
        }
    }

    /** A server with every endpoint available, WHOIS off, history and feeds in the temp dir. */
    private ApiServer newServer() {
        PrintStream log = new PrintStream(new ByteArrayOutputStream(), true, StandardCharsets.UTF_8);
        ThreatFeedService feeds = new ThreatFeedService(ThreatFeedSettings.defaults(),
                new FeedCache(tempDir.resolve("feeds")), new FakeFeedFetcher(),
                Clock.fixed(Instant.parse("2026-11-21T10:00:00Z"), ZoneOffset.UTC));
        return new ApiServer(new ScanService(PhishNetConfig.defaultConfig(), null), log)
                .withHistory(new HistoryDatabase(tempDir.resolve("history.db"), false, log))
                .withFeeds(feeds);
    }

    private Response send(String method, String path, String apiKey, String json) throws Exception {
        HttpRequest.Builder request = HttpRequest.newBuilder(URI.create("http://localhost:" + server.port() + path))
                .method(method, json == null ? HttpRequest.BodyPublishers.noBody()
                        : HttpRequest.BodyPublishers.ofString(json));
        if (json != null) {
            request.header("Content-Type", "application/json");
        }
        if (apiKey != null) {
            request.header(ApiServer.API_KEY_HEADER, apiKey);
        }
        HttpResponse<String> response = http.send(request.build(), HttpResponse.BodyHandlers.ofString());
        JsonNode body = response.body().isEmpty() ? null : MAPPER.readTree(response.body());
        return new Response(response.statusCode(), body, response);
    }

    private Response scan(String apiKey) throws Exception {
        return send("POST", "/api/scan/url", apiKey, SCAN_BODY);
    }

    // --- authentication --------------------------------------------------------------

    @Test
    void validKeyPassesOnEveryProtectedEndpoint() throws Exception {
        server = newServer().withApiKey(KEY).start(0);

        assertEquals(200, scan(KEY).status());
        assertEquals("MEDIUM", scan(KEY).body().get("level").asText());
        assertEquals(200, send("POST", "/api/scan/email", KEY,
                "{\"raw\":\"From: a@example.com\\nSubject: hi\\n\\nhello\"}").status());
        for (String path : List.of("/api/history", "/api/history/stats", "/api/feeds/status", "/api/auth/check")) {
            assertEquals(200, send("GET", path, KEY, null).status(), path);
        }
        assertEquals("ok", send("GET", "/api/auth/check", KEY, null).body().get("status").asText());
    }

    @Test
    void missingOrInvalidKeyGets401WithTheSameJsonError() throws Exception {
        server = newServer().withApiKey(KEY).start(0);

        Response missing = scan(null);
        assertEquals(401, missing.status());
        assertEquals(ApiServer.UNAUTHORIZED_MESSAGE, missing.body().get("error").asText());
        assertTrue(missing.header("Content-Type").startsWith("application/json"));

        // Nothing distinguishes a near miss from a wild guess.
        for (String wrong : List.of("", "wrong", KEY.substring(0, KEY.length() - 1), KEY + "x", KEY.toUpperCase(Locale.ROOT))) {
            Response response = scan(wrong);
            assertEquals(401, response.status(), "'" + wrong + "'");
            assertEquals(missing.body(), response.body(), "'" + wrong + "'");
        }
    }

    @Test
    void everyProtectedEndpointRequiresTheKey() throws Exception {
        server = newServer().withApiKey(KEY).start(0);

        assertEquals(401, send("POST", "/api/scan/email", null, "{\"raw\":\"x\"}").status());
        for (String path : List.of("/api/history", "/api/history/stats", "/api/feeds/status", "/api/auth/check")) {
            assertEquals(401, send("GET", path, null, null).status(), path);
            assertEquals(401, send("GET", path, "wrong-key", null).status(), path);
        }
        // Unknown paths don't reveal themselves without a key; with one they're a plain 404.
        assertEquals(401, send("GET", "/api/nope", null, null).status());
        assertEquals(404, send("GET", "/api/nope", KEY, null).status());
    }

    @Test
    void healthStaysOpenWithoutAKey() throws Exception {
        server = newServer().withApiKey(KEY).start(0);

        Response health = send("GET", "/api/health", null, null);

        assertEquals(200, health.status());
        assertEquals("ok", health.body().get("status").asText());
        assertEquals(200, send("GET", "/api/health", "wrong-key", null).status());
    }

    @Test
    void withoutAKeyEverythingIsOpenAsBefore() throws Exception {
        // What serve does with --no-auth: no withApiKey().
        server = newServer().start(0);

        assertEquals(200, scan(null).status());
        assertEquals(200, send("GET", "/api/history", null, null).status());
        assertEquals(200, send("GET", "/api/auth/check", null, null).status());
        assertEquals(200, scan("any-key-is-ignored").status());
    }

    @Test
    void extensionPreflightNeedsNoKeyAndAllowsTheKeyHeader() throws Exception {
        server = newServer().withApiKey(KEY).start(0);
        HttpRequest preflight = HttpRequest.newBuilder(URI.create("http://localhost:" + server.port() + "/api/scan/url"))
                .method("OPTIONS", HttpRequest.BodyPublishers.noBody())
                .header("Origin", "chrome-extension://abcdefghijklmnopabcdefghijklmnop")
                .header("Access-Control-Request-Method", "POST")
                .header("Access-Control-Request-Headers", "content-type,x-api-key")
                .build();

        HttpResponse<String> response = http.send(preflight, HttpResponse.BodyHandlers.ofString());

        assertEquals(204, response.statusCode());
        assertTrue(response.headers().firstValue("Access-Control-Allow-Headers").orElse("").contains("X-API-Key"));
    }

    @Test
    void unauthorizedResponsesToAnExtensionAreReadable() throws Exception {
        server = newServer().withApiKey(KEY).start(0);
        HttpRequest request = HttpRequest.newBuilder(URI.create("http://localhost:" + server.port() + "/api/auth/check"))
                .header("Origin", "moz-extension://4f3c2a10-8e7b-4d6a-9c1f-2b3e4d5f6a7b")
                .GET().build();

        HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());

        assertEquals(401, response.statusCode());
        assertEquals("moz-extension://4f3c2a10-8e7b-4d6a-9c1f-2b3e4d5f6a7b",
                response.headers().firstValue("Access-Control-Allow-Origin").orElse(null));
    }

    // --- rate limiting ---------------------------------------------------------------

    private void advanceSeconds(long seconds) {
        nanos.addAndGet(TimeUnit.SECONDS.toNanos(seconds));
    }

    @Test
    void scansOverTheLimitGet429WithRetryAfter() throws Exception {
        server = newServer().withApiKey(KEY).withRateLimiter(new RateLimiter(3, nanos::get)).start(0);

        for (int i = 1; i <= 3; i++) {
            assertEquals(200, scan(KEY).status(), "scan " + i);
        }
        Response limited = scan(KEY);

        assertEquals(429, limited.status());
        assertEquals("20", limited.header("Retry-After"), "one scan every 60 / 3 = 20 seconds");
        assertEquals(ApiServer.rateLimitMessage(3, 20), limited.body().get("error").asText());
        assertEquals("Too many scan requests: the limit is 3 per minute per client. Try again in 20 seconds.",
                limited.body().get("error").asText());
        // Email scans share the same allowance.
        assertEquals(429, send("POST", "/api/scan/email", KEY, "{\"raw\":\"From: a@b.c\\n\\nhi\"}").status());
    }

    @Test
    void limitResetsAfterTheWindow() throws Exception {
        server = newServer().withRateLimiter(new RateLimiter(2, nanos::get)).start(0);
        scan(null);
        scan(null);
        assertEquals(429, scan(null).status());

        advanceSeconds(60);

        assertEquals(200, scan(null).status());
        assertEquals(200, scan(null).status());
        assertEquals(429, scan(null).status());
    }

    @Test
    void onlyScansAreRateLimited() throws Exception {
        server = newServer().withApiKey(KEY).withRateLimiter(new RateLimiter(1, nanos::get)).start(0);
        scan(KEY);
        assertEquals(429, scan(KEY).status());

        for (int i = 0; i < 5; i++) {
            assertEquals(200, send("GET", "/api/history", KEY, null).status());
            assertEquals(200, send("GET", "/api/health", null, null).status());
            assertEquals(200, send("GET", "/api/auth/check", KEY, null).status());
        }
    }

    @Test
    void rejectedKeysDoNotUseUpTheAllowance() throws Exception {
        server = newServer().withApiKey(KEY).withRateLimiter(new RateLimiter(2, nanos::get)).start(0);

        for (int i = 0; i < 10; i++) {
            assertEquals(401, scan("wrong-key").status());
        }

        assertEquals(200, scan(KEY).status());
        assertEquals(200, scan(KEY).status());
    }

    @Test
    void retryAfterIsReadableByTheExtension() throws Exception {
        server = newServer().withRateLimiter(new RateLimiter(1, nanos::get)).start(0);
        scan(null);
        HttpRequest request = HttpRequest.newBuilder(URI.create("http://localhost:" + server.port() + "/api/scan/url"))
                .header("Origin", "chrome-extension://abcdefghijklmnopabcdefghijklmnop")
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(SCAN_BODY)).build();

        HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());

        assertEquals(429, response.statusCode());
        assertEquals("Retry-After", response.headers().firstValue("Access-Control-Expose-Headers").orElse(null));
        assertEquals("60", response.headers().firstValue("Retry-After").orElse(null));
    }

    @Test
    void zeroMeansNoLimit() throws Exception {
        server = newServer().withRateLimit(0).start(0);

        for (int i = 0; i < 25; i++) {
            assertEquals(200, scan(null).status());
        }
        assertNull(scan(null).header("Retry-After"));
    }

    @Test
    void rateLimitMessageUsesSingularForOneSecond() {
        assertEquals("Too many scan requests: the limit is 60 per minute per client. Try again in 1 second.",
                ApiServer.rateLimitMessage(60, 1));
    }
}
