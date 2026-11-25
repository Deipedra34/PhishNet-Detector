package com.phishnet.api;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.phishnet.model.PhishNetConfig;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Accept-Language picks the language of the API's error messages and human-readable labels. */
class ApiLanguageTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String IP_URL = "{\"url\":\"http://192.168.1.10/login\"}";

    private final HttpClient http = HttpClient.newHttpClient();
    private ApiServer server;

    private record Response(int status, String contentLanguage, JsonNode body) {
    }

    @AfterEach
    void stopServer() {
        if (server != null) {
            server.stop();
        }
    }

    private void startServer(String apiKey) {
        ScanService scanner = new ScanService(PhishNetConfig.defaultConfig(), null);
        server = new ApiServer(scanner, new PrintStream(new ByteArrayOutputStream(), true, StandardCharsets.UTF_8))
                .withApiKey(apiKey)
                .start(0);
    }

    private Response post(String path, String json, String acceptLanguage) throws IOException, InterruptedException {
        HttpRequest.Builder request = HttpRequest.newBuilder(uri(path))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(json));
        return send(acceptLanguage == null ? request : request.header("Accept-Language", acceptLanguage));
    }

    private Response get(String path, String acceptLanguage) throws IOException, InterruptedException {
        return send(HttpRequest.newBuilder(uri(path)).header("Accept-Language", acceptLanguage).GET());
    }

    private URI uri(String path) {
        return URI.create("http://localhost:" + server.port() + path);
    }

    private Response send(HttpRequest.Builder request) throws IOException, InterruptedException {
        HttpResponse<String> response = http.send(request.build(), HttpResponse.BodyHandlers.ofString());
        return new Response(response.statusCode(), response.headers().firstValue("Content-Language").orElse(null),
                MAPPER.readTree(response.body()));
    }

    // --- header parsing --------------------------------------------------------------

    @Test
    void picksTheMostPreferredSupportedLanguage() {
        assertLanguage("en", null);
        assertLanguage("en", "");
        assertLanguage("tr", "tr");
        assertLanguage("tr", "tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7");
        assertLanguage("en", "en-GB,en;q=0.9,tr;q=0.8");
        assertLanguage("tr", "de-DE, tr;q=0.8, en;q=0.5");
        assertLanguage("tr", "en;q=0.1, tr;q=0.9");
        assertLanguage("en", "de, fr;q=0.5");
        assertLanguage("en", "*");
        assertLanguage("en", "tr;q=0");
        assertLanguage("en", ";;;==not a header");
    }

    private static void assertLanguage(String expected, String header) {
        assertEquals(expected, ApiLanguage.fromHeader(header).locale().getLanguage(), "Accept-Language: " + header);
    }

    // --- over HTTP ---------------------------------------------------------------------

    @Test
    void scanResultsAreEnglishByDefault() throws Exception {
        startServer(null);
        Response response = post("/api/scan/url", IP_URL, null);
        assertEquals(200, response.status());
        assertEquals("en", response.contentLanguage());
        JsonNode signal = response.body().get("signals").get(0);
        assertEquals("ipAddressHost", signal.get("id").asText());
        assertEquals("URL uses a raw IP address instead of a domain name", signal.get("description").asText());
        assertTrue(response.body().get("recommendation").asText().startsWith("No strong phishing indicators found")
                || response.body().get("recommendation").asText().startsWith("Some phishing indicators found"),
                response.body().toString());
    }

    @Test
    void scanResultsFollowAcceptLanguageButKeysAndValuesStayEnglish() throws Exception {
        startServer(null);
        Response english = post("/api/scan/url", IP_URL, "en");
        Response turkish = post("/api/scan/url", IP_URL, "tr-TR,tr;q=0.9,en;q=0.5");
        assertEquals(200, turkish.status());
        assertEquals("tr", turkish.contentLanguage());

        // Same structure, ids, and machine-readable values in both languages.
        assertEquals(fieldNames(english.body()), fieldNames(turkish.body()));
        assertEquals(english.body().get("level"), turkish.body().get("level"));
        assertEquals(english.body().get("score"), turkish.body().get("score"));
        assertEquals("URL", turkish.body().get("type").asText());
        JsonNode signal = turkish.body().get("signals").get(0);
        assertEquals("ipAddressHost", signal.get("id").asText());
        assertEquals("URL", signal.get("category").asText());
        assertEquals("SKIPPED", turkish.body().get("domainAge").get("status").asText());

        // Only the human-readable text is translated.
        assertEquals("URL, alan adı yerine doğrudan bir IP adresi kullanıyor", signal.get("description").asText());
        String recommendation = turkish.body().get("recommendation").asText();
        assertTrue(recommendation.startsWith("Güçlü bir oltalama belirtisi bulunmadı")
                || recommendation.startsWith("Bazı oltalama belirtileri bulundu"), recommendation);
    }

    private static String fieldNames(JsonNode node) {
        StringBuilder names = new StringBuilder();
        node.fieldNames().forEachRemaining(name -> names.append(name).append(','));
        return names.toString();
    }

    @Test
    void errorMessagesFollowAcceptLanguage() throws Exception {
        startServer(null);
        assertEquals("Missing required field 'url'", post("/api/scan/url", "{}", "en").body().get("error").asText());
        assertEquals("Gerekli 'url' alanı eksik", post("/api/scan/url", "{}", "tr").body().get("error").asText());
        assertEquals("İstek gövdesi geçerli bir JSON değil",
                post("/api/scan/url", "not json", "tr").body().get("error").asText());

        Response missing = get("/api/does-not-exist", "tr");
        assertEquals(404, missing.status());
        assertEquals("GET /api/does-not-exist uç noktası bulunamadı", missing.body().get("error").asText());
        assertEquals("Endpoint GET /api/does-not-exist not found",
                get("/api/does-not-exist", "en").body().get("error").asText());

        assertEquals("Bu sunucuda tarama geçmişi kullanılamıyor", get("/api/history", "tr").body().get("error").asText());
    }

    @Test
    void anUnsupportedLanguageGetsEnglishErrors() throws Exception {
        startServer(null);
        Response response = post("/api/scan/url", "{}", "de-DE,fr;q=0.8");
        assertEquals("en", response.contentLanguage());
        assertEquals("Missing required field 'url'", response.body().get("error").asText());
    }

    @Test
    void theApiKeyErrorIsTranslatedToo() throws Exception {
        startServer("the-key-0123456789");
        Response turkish = post("/api/scan/url", IP_URL, "tr");
        assertEquals(401, turkish.status());
        assertTrue(turkish.body().get("error").asText().startsWith("API anahtarı eksik veya geçersiz."),
                turkish.body().toString());
        assertEquals(ApiServer.UNAUTHORIZED_MESSAGE, post("/api/scan/url", IP_URL, null).body().get("error").asText());
    }
}
