package com.phishnet.cli;

import com.phishnet.analyzer.WhoisClient;
import com.phishnet.api.ApiKeyStore;
import com.phishnet.api.ApiServer;
import com.phishnet.feeds.FakeFeedFetcher;
import com.phishnet.feeds.FeedCache;
import com.phishnet.feeds.ThreatFeedService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import picocli.CommandLine;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@code phishnet serve}'s API key and rate limit options, end to end: the command
 * starts a real server on a free port, with the key file, history, and feed cache in
 * a JUnit temp directory - never in ~/.phishnet.
 */
class ServeAuthTest {

    private record Captured(int exitCode, String stdout, String stderr) {
    }

    private static final WhoisClient OFFLINE_WHOIS = (server, query, timeout) -> {
        throw new IOException("network disabled in tests");
    };

    @TempDir
    Path tempDir;

    private final Map<String, String> env = new HashMap<>();
    private final HttpClient http = HttpClient.newHttpClient();
    private final List<ServeCommand> started = new ArrayList<>();

    @AfterEach
    void stopServers() {
        for (ServeCommand command : started) {
            if (command.startedServer() != null) {
                command.startedServer().stop();
            }
        }
    }

    private Path keyFile() {
        return tempDir.resolve("keys").resolve("api-key");
    }

    private Captured serve(String... extra) {
        ByteArrayOutputStream outBytes = new ByteArrayOutputStream();
        ByteArrayOutputStream errBytes = new ByteArrayOutputStream();
        PrintStream out = new PrintStream(outBytes, true, StandardCharsets.UTF_8);
        PrintStream err = new PrintStream(errBytes, true, StandardCharsets.UTF_8);
        ServeCommand command = new ServeCommand(out, err, OFFLINE_WHOIS,
                settings -> new ThreatFeedService(settings, new FeedCache(tempDir.resolve("feeds")),
                        new FakeFeedFetcher(), Clock.fixed(Instant.parse("2026-11-21T10:00:00Z"), ZoneOffset.UTC)),
                env);
        started.add(command);
        List<String> args = new ArrayList<>(List.of("--port", "0", "--no-whois", "--no-dashboard",
                "--history-db", tempDir.resolve("history.db").toString(),
                "--api-key-file", keyFile().toString()));
        args.addAll(Arrays.asList(extra));
        CommandLine cmd = new CommandLine(command);
        cmd.setOut(new PrintWriter(out, true, StandardCharsets.UTF_8));
        cmd.setErr(new PrintWriter(err, true, StandardCharsets.UTF_8));
        int code = cmd.execute(args.toArray(String[]::new));
        return new Captured(code, outBytes.toString(StandardCharsets.UTF_8), errBytes.toString(StandardCharsets.UTF_8));
    }

    private int lastPort() {
        return started.get(started.size() - 1).startedServer().port();
    }

    private int status(String method, String path, String apiKey) throws Exception {
        HttpRequest.Builder request = HttpRequest.newBuilder(URI.create("http://localhost:" + lastPort() + path));
        if (method.equals("POST")) {
            request.header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString("{\"url\":\"http://paypa1.com\"}"));
        }
        if (apiKey != null) {
            request.header(ApiServer.API_KEY_HEADER, apiKey);
        }
        return http.send(request.build(), HttpResponse.BodyHandlers.discarding()).statusCode();
    }

    private String storedKey() throws IOException {
        return Files.readString(keyFile()).strip();
    }

    @Test
    void firstRunGeneratesPrintsAndRequiresAKey() throws Exception {
        Captured result = serve();

        assertEquals(0, result.exitCode(), result.stderr());
        String key = storedKey();
        assertTrue(result.stdout().contains("Generated a new API key and saved it to"), result.stdout());
        assertTrue(result.stdout().contains("    " + key), "the new key is printed once, in full");
        assertTrue(result.stdout().contains("X-API-Key header"));
        assertTrue(result.stdout().contains("Rate limit: 60 scan requests per minute per client"), result.stdout());

        assertEquals(401, status("POST", "/api/scan/url", null));
        assertEquals(200, status("POST", "/api/scan/url", key));
        assertEquals(200, status("GET", "/api/health", null));
    }

    @Test
    void laterRunsReuseTheKeyWithoutPrintingIt() throws Exception {
        serve();
        String key = storedKey();
        started.get(0).startedServer().stop();

        Captured second = serve();

        assertEquals(0, second.exitCode(), second.stderr());
        assertFalse(second.stdout().contains(key), "the key is only printed when it's created");
        assertTrue(second.stdout().contains("API key required (X-API-Key header): from " + keyFile().toAbsolutePath()),
                second.stdout());
        assertEquals(200, status("GET", "/api/auth/check", key));
    }

    @Test
    void noAuthBypassesTheKeyAndWarns() throws Exception {
        Captured result = serve("--no-auth");

        assertEquals(0, result.exitCode(), result.stderr());
        assertTrue(result.stderr().contains("API authentication is disabled (--no-auth)"), result.stderr());
        assertFalse(Files.exists(keyFile()), "--no-auth never creates a key");
        assertEquals(200, status("POST", "/api/scan/url", null));
        assertEquals(200, status("GET", "/api/history", null));
    }

    @Test
    void regenerateKeyReplacesTheOldKey() throws Exception {
        serve();
        String oldKey = storedKey();
        started.get(0).startedServer().stop();

        Captured result = serve("--regenerate-key");

        String newKey = storedKey();
        assertEquals(0, result.exitCode(), result.stderr());
        assertNotEquals(oldKey, newKey);
        assertTrue(result.stdout().contains("Replaced the API key with a new one"), result.stdout());
        assertTrue(result.stdout().contains("    " + newKey));
        assertEquals(401, status("GET", "/api/auth/check", oldKey));
        assertEquals(200, status("GET", "/api/auth/check", newKey));
    }

    @Test
    void keyFromTheEnvironmentIsUsedAndNotWritten() throws Exception {
        env.put(ApiKeyStore.KEY_ENV, "key-from-the-environment-42");

        Captured result = serve();

        assertEquals(0, result.exitCode(), result.stderr());
        assertTrue(result.stdout().contains("from $" + ApiKeyStore.KEY_ENV), result.stdout());
        assertFalse(result.stdout().contains("key-from-the-environment-42"));
        assertFalse(Files.exists(keyFile()));
        assertEquals(200, status("GET", "/api/auth/check", "key-from-the-environment-42"));
    }

    @Test
    void rateLimitFlagOverridesTheConfig() throws Exception {
        Captured result = serve("--no-auth", "--rate-limit", "2");

        assertTrue(result.stdout().contains("Rate limit: 2 scan requests per minute per client"), result.stdout());
        assertEquals(200, status("POST", "/api/scan/url", null));
        assertEquals(200, status("POST", "/api/scan/url", null));
        assertEquals(429, status("POST", "/api/scan/url", null));
    }

    @Test
    void rateLimitComesFromTheConfigFile() throws Exception {
        Path config = tempDir.resolve("config.yaml");
        String bundled = new String(getClass().getResourceAsStream("/phishnet-config.yaml").readAllBytes(),
                StandardCharsets.UTF_8);
        Files.writeString(config, bundled.replace("rateLimitPerMinute: 60", "rateLimitPerMinute: 1"));

        Captured result = serve("--no-auth", "--config", config.toString());

        assertTrue(result.stdout().contains("Rate limit: 1 scan requests per minute per client"), result.stdout());
        assertEquals(200, status("POST", "/api/scan/url", null));
        assertEquals(429, status("POST", "/api/scan/url", null));
    }

    @Test
    void rateLimitZeroTurnsItOff() throws Exception {
        Captured result = serve("--no-auth", "--rate-limit", "0");

        assertTrue(result.stdout().contains("Rate limit: off"), result.stdout());
        for (int i = 0; i < 5; i++) {
            assertEquals(200, status("POST", "/api/scan/url", null));
        }
    }

    @Test
    void invalidCombinationsFailWithoutStarting() throws Exception {
        assertEquals(2, serve("--no-auth", "--regenerate-key").exitCode());
        assertEquals(2, serve("--rate-limit", "-5").exitCode());

        env.put(ApiKeyStore.KEY_ENV, "key-from-the-environment-42");
        Captured envAndRegenerate = serve("--regenerate-key");
        assertEquals(1, envAndRegenerate.exitCode());
        assertTrue(envAndRegenerate.stderr().contains("set that variable to a new value instead"));

        assertTrue(started.stream().allMatch(command -> command.startedServer() == null));
        assertFalse(Files.exists(keyFile()), "no key file is created when the command line is rejected");
    }

    @Test
    void unusableKeyFileIsReportedWithoutStarting() throws Exception {
        Files.createDirectories(keyFile().getParent());
        Files.writeString(keyFile(), "too short");

        Captured result = serve();

        assertEquals(1, result.exitCode());
        assertTrue(result.stderr().contains("could not load the API key"), result.stderr());
        assertNull(started.get(0).startedServer());
    }

    @Test
    void helpDocumentsTheNewOptions() {
        Captured help = serve("--help");
        for (String option : List.of("--no-auth", "--regenerate-key", "--rate-limit", "--api-key-file")) {
            assertTrue(help.stdout().contains(option), option);
        }
    }
}
