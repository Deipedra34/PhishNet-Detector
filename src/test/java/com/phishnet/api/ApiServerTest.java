package com.phishnet.api;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.phishnet.analyzer.WhoisClient;
import com.phishnet.model.PhishNetConfig;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.LocalDate;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Exercises the REST API over real HTTP: each test starts an {@link ApiServer}
 * on a free port and talks to it with the JDK's HttpClient. WHOIS is either
 * skipped or faked, so nothing here leaves the machine.
 */
class ApiServerTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String BOUNDARY = "----PhishNetTestBoundary";

    private final HttpClient http = HttpClient.newHttpClient();
    private final ByteArrayOutputStream serverLog = new ByteArrayOutputStream();
    private ApiServer server;

    private record Response(int status, JsonNode body) {
    }

    /** Starts a server with WHOIS disabled (the API equivalent of --no-whois). */
    private void startServer() {
        startServer(null);
    }

    private void startServer(WhoisClient whoisClient) {
        ScanService scanner = new ScanService(PhishNetConfig.defaultConfig(), whoisClient);
        server = new ApiServer(scanner, new PrintStream(serverLog, true, StandardCharsets.UTF_8)).start(0);
    }

    @AfterEach
    void stopServer() {
        if (server != null) {
            server.stop();
        }
    }

    private URI uri(String path) {
        return URI.create("http://localhost:" + server.port() + path);
    }

    private Response send(HttpRequest request) throws IOException, InterruptedException {
        HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
        assertTrue(response.headers().firstValue("Content-Type").orElse("").startsWith("application/json"),
                "every response should be JSON, got: " + response.headers().firstValue("Content-Type"));
        return new Response(response.statusCode(), MAPPER.readTree(response.body()));
    }

    private Response get(String path) throws IOException, InterruptedException {
        return send(HttpRequest.newBuilder(uri(path)).GET().build());
    }

    private Response postJson(String path, String json) throws IOException, InterruptedException {
        return send(HttpRequest.newBuilder(uri(path))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(json))
                .build());
    }

    private Response postMultipart(String path, String fieldName, String fileName, byte[] content)
            throws IOException, InterruptedException {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        body.writeBytes(("--" + BOUNDARY + "\r\n"
                + "Content-Disposition: form-data; name=\"" + fieldName + "\"; filename=\"" + fileName + "\"\r\n"
                + "Content-Type: message/rfc822\r\n\r\n").getBytes(StandardCharsets.UTF_8));
        body.writeBytes(content);
        body.writeBytes(("\r\n--" + BOUNDARY + "--\r\n").getBytes(StandardCharsets.UTF_8));
        return send(HttpRequest.newBuilder(uri(path))
                .header("Content-Type", "multipart/form-data; boundary=" + BOUNDARY)
                .POST(HttpRequest.BodyPublishers.ofByteArray(body.toByteArray()))
                .build());
    }

    private static byte[] fixture(String name) throws IOException {
        try (InputStream in = ApiServerTest.class.getResourceAsStream("/emails/" + name)) {
            if (in == null) {
                throw new IllegalStateException("Missing fixture: " + name);
            }
            return in.readAllBytes();
        }
    }

    private static boolean hasSignal(JsonNode body, String id) {
        for (JsonNode signal : body.get("signals")) {
            if (id.equals(signal.get("id").asText())) {
                return true;
            }
        }
        return false;
    }

    private static void assertError(Response response, int expectedStatus, String expectedMessagePart) {
        assertEquals(expectedStatus, response.status(), response.body().toString());
        assertTrue(response.body().has("error"), response.body().toString());
        assertTrue(response.body().get("error").asText().contains(expectedMessagePart),
                response.body().toString());
    }

    // --- health ----------------------------------------------------------------

    @Test
    void healthCheckReturnsOk() throws Exception {
        startServer();

        Response response = get("/api/health");

        assertEquals(200, response.status());
        assertEquals("ok", response.body().get("status").asText());
    }

    // --- URL scans -------------------------------------------------------------

    @Test
    void urlScanReturnsFullResult() throws Exception {
        startServer();

        Response response = postJson("/api/scan/url", "{\"url\":\"http://192.168.1.1/login\"}");

        assertEquals(200, response.status());
        JsonNode body = response.body();
        assertEquals("http://192.168.1.1/login", body.get("target").asText());
        assertEquals("URL", body.get("type").asText());
        assertTrue(body.get("score").isInt());
        assertTrue(body.get("level").asText().matches("LOW|MEDIUM|HIGH"));
        assertFalse(body.get("recommendation").asText().isEmpty());
        assertTrue(hasSignal(body, "ipAddressHost"), body.toString());
        assertEquals("SKIPPED", body.get("domainAge").get("status").asText());
    }

    @Test
    void urlScanIncludesDomainAgeWhenWhoisAnswers() throws Exception {
        String created = LocalDate.now().minusDays(10).toString();
        WhoisClient fakeRegistry = (server, query, timeoutMillis) ->
                "Domain Name: " + query.toUpperCase() + "\r\nCreation Date: " + created + "T10:00:00Z\r\n";
        startServer(fakeRegistry);

        Response response = postJson("/api/scan/url", "{\"url\":\"https://fresh-site.com/login\"}");

        assertEquals(200, response.status());
        JsonNode domainAge = response.body().get("domainAge");
        assertEquals("KNOWN", domainAge.get("status").asText());
        assertEquals("fresh-site.com", domainAge.get("domain").asText());
        assertEquals(created, domainAge.get("creationDate").asText());
        assertEquals(10, domainAge.get("ageDays").asInt());
        assertTrue(hasSignal(response.body(), "domainAgeNew"), response.body().toString());
    }

    @Test
    void whoisResultsAreNotCachedAcrossRequests() throws Exception {
        // The CLI caches lookups (and failed servers) for one run; a long-running
        // server must not carry that cache from one request into the next.
        AtomicInteger calls = new AtomicInteger();
        WhoisClient failsOnce = (server, query, timeoutMillis) -> {
            if (calls.incrementAndGet() == 1) {
                throw new IOException("transient registry outage");
            }
            return "Domain Name: " + query.toUpperCase() + "\r\nCreation Date: 2001-01-01T00:00:00Z\r\n";
        };
        startServer(failsOnce);

        Response first = postJson("/api/scan/url", "{\"url\":\"https://example.com\"}");
        Response second = postJson("/api/scan/url", "{\"url\":\"https://example.com\"}");

        assertEquals("UNKNOWN", first.body().get("domainAge").get("status").asText());
        assertEquals("KNOWN", second.body().get("domainAge").get("status").asText());
    }

    @Test
    void urlScanMatchesCliScoring() throws Exception {
        startServer();

        Response phishy = postJson("/api/scan/url", "{\"url\":\"https://bit.ly/xyz\"}");
        Response clean = postJson("/api/scan/url", "{\"url\":\"https://example.com\"}");

        assertTrue(hasSignal(phishy.body(), "urlShortener"));
        assertTrue(phishy.body().get("score").asInt() > clean.body().get("score").asInt());
    }

    @Test
    void urlScanRejectsMissingOrInvalidInput() throws Exception {
        startServer();

        assertError(postJson("/api/scan/url", ""), 400, "empty");
        assertError(postJson("/api/scan/url", "{}"), 400, "Missing required field 'url'");
        assertError(postJson("/api/scan/url", "{\"url\":null}"), 400, "Missing required field 'url'");
        assertError(postJson("/api/scan/url", "{\"url\":\"   \"}"), 400, "must not be empty");
        assertError(postJson("/api/scan/url", "{\"url\":42}"), 400, "must be a string");
        assertError(postJson("/api/scan/url", "{not json"), 400, "not valid JSON");
        assertError(postJson("/api/scan/url", "[\"https://example.com\"]"), 400, "JSON object");
        assertError(postJson("/api/scan/url", "{\"url\":\"https://x.com/" + "a".repeat(ApiServer.MAX_URL_LENGTH) + "\"}"),
                400, "too long");
    }

    // --- email scans -----------------------------------------------------------

    @Test
    void emailScanAcceptsEmlUpload() throws Exception {
        startServer();

        Response response = postMultipart("/api/scan/email", ApiServer.EMAIL_UPLOAD_FIELD,
                "suspicious.eml", fixture("phishing_html_shortener.eml"));

        assertEquals(200, response.status(), response.body().toString());
        JsonNode body = response.body();
        assertEquals("suspicious.eml", body.get("target").asText());
        assertEquals("EMAIL", body.get("type").asText());
        assertTrue(hasSignal(body, "urlShortener"), body.toString());
        assertEquals("notice@example.com", body.get("email").get("from").asText());
        assertEquals("http://bit.ly/xyz123", body.get("email").get("links").get(0).asText());
    }

    @Test
    void emailScanAcceptsRawTextInJsonBody() throws Exception {
        startServer();
        String raw = new String(fixture("phishing_urgency_en.eml"), StandardCharsets.UTF_8);

        Response response = postJson("/api/scan/email", MAPPER.writeValueAsString(Map.of("raw", raw)));

        assertEquals(200, response.status(), response.body().toString());
        assertEquals("EMAIL", response.body().get("type").asText());
        assertTrue(hasSignal(response.body(), "urgencyLanguage"), response.body().toString());
        assertEquals("Important notice about your account", response.body().get("email").get("subject").asText());
    }

    @Test
    void legitimateEmailScoresLow() throws Exception {
        startServer();

        Response response = postMultipart("/api/scan/email", ApiServer.EMAIL_UPLOAD_FIELD,
                "legitimate.eml", fixture("legitimate.eml"));

        assertEquals(200, response.status());
        assertEquals("LOW", response.body().get("level").asText());
    }

    @Test
    void emailScanRejectsMissingOrInvalidInput() throws Exception {
        startServer();

        assertError(postJson("/api/scan/email", ""), 400, "empty");
        assertError(postJson("/api/scan/email", "{}"), 400, "Missing required field 'raw'");
        assertError(postJson("/api/scan/email", "{\"raw\":\"\"}"), 400, "must not be empty");
        assertError(postJson("/api/scan/email", "{\"raw\":[1,2]}"), 400, "must be a string");
        assertError(postMultipart("/api/scan/email", "attachment", "x.eml", fixture("legitimate.eml")),
                400, "form field named 'file'");
        assertError(postMultipart("/api/scan/email", ApiServer.EMAIL_UPLOAD_FIELD, "empty.eml", new byte[0]),
                400, "empty");
    }

    // The size-limit tests use a 1 KB limit and 4 KB bodies rather than the real 5 MB:
    // a small rejected body arrives in full straight away, so the server can drain it
    // and answer cleanly. With megabytes still in flight, the server closing the
    // connection early can reset it before the client reads the 413 (notably on Linux).
    private static final int SMALL_LIMIT = 1024;

    private void startServerWithSmallLimit() {
        ScanService scanner = new ScanService(PhishNetConfig.defaultConfig(), null);
        server = new ApiServer(scanner, new PrintStream(serverLog, true, StandardCharsets.UTF_8), SMALL_LIMIT)
                .start(0);
    }

    private static String oversizedText() {
        char[] chars = new char[SMALL_LIMIT * 4];
        Arrays.fill(chars, 'a');
        return new String(chars);
    }

    /** POSTs without a Content-Length header (chunked), so only the streaming limit can catch it. */
    private Response postChunked(String path, String contentType, byte[] body) throws IOException, InterruptedException {
        return send(HttpRequest.newBuilder(uri(path))
                .header("Content-Type", contentType)
                .POST(HttpRequest.BodyPublishers.ofInputStream(() -> new java.io.ByteArrayInputStream(body)))
                .build());
    }

    @Test
    void defaultRequestLimitIsFiveMegabytes() {
        assertEquals(5L * 1024 * 1024, ApiServer.MAX_REQUEST_BYTES);
    }

    @Test
    void oversizedRequestsWithDeclaredLengthAreRejected() throws Exception {
        startServerWithSmallLimit();
        String big = oversizedText();

        assertError(postJson("/api/scan/email", MAPPER.writeValueAsString(Map.of("raw", big))),
                413, "too large (max 1024 bytes)");
        assertError(postMultipart("/api/scan/email", ApiServer.EMAIL_UPLOAD_FIELD, "huge.eml",
                big.getBytes(StandardCharsets.US_ASCII)), 413, "too large");
        assertError(postJson("/api/scan/url", MAPPER.writeValueAsString(Map.of("url", "https://x.com/" + big))),
                413, "too large");
    }

    @Test
    void oversizedChunkedRequestsAreRejected() throws Exception {
        startServerWithSmallLimit();
        String big = oversizedText();

        byte[] json = MAPPER.writeValueAsBytes(Map.of("raw", big));
        assertError(postChunked("/api/scan/email", "application/json", json), 413, "too large");
    }

    @Test
    void requestsWithinLimitStillWork() throws Exception {
        startServerWithSmallLimit();

        Response response = postJson("/api/scan/url", "{\"url\":\"https://bit.ly/xyz\"}");

        assertEquals(200, response.status());
    }

    // --- routing / error shape -------------------------------------------------

    @Test
    void unknownRouteAndWrongMethodReturnJsonErrors() throws Exception {
        startServer();

        assertError(get("/api/does-not-exist"), 404, "not found");
        assertEquals(405, get("/api/scan/url").status());
        assertTrue(get("/api/scan/url").body().has("error"));
    }

    @Test
    void unexpectedFailureReturns500WithoutLeakingStackTrace() throws Exception {
        // A config with no scoring section makes the analyzers throw a NullPointerException
        // mid-scan - standing in for any unexpected internal bug.
        PhishNetConfig broken = new PhishNetConfig(List.of(), List.of(), List.of(), Map.of(), null);
        server = new ApiServer(new ScanService(broken, null),
                new PrintStream(serverLog, true, StandardCharsets.UTF_8)).start(0);

        Response response = postJson("/api/scan/url", "{\"url\":\"https://example.com\"}");

        assertError(response, 500, "Internal server error");
        assertEquals(1, response.body().size(), "error body should carry nothing but the message");
        assertFalse(response.body().toString().contains("NullPointerException"));
        // The details still reach the server-side log.
        assertTrue(serverLog.toString(StandardCharsets.UTF_8).contains("NullPointerException"));
    }

    @Test
    void serverCanBeStoppedAndPortReported() {
        startServer();
        assertTrue(server.port() > 0);
        server.stop();
        server = null;
    }
}
