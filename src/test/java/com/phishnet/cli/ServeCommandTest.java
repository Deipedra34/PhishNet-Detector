package com.phishnet.cli;

import com.phishnet.analyzer.WhoisClient;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Command-line handling of {@code phishnet serve}. These only cover paths that
 * return before a server is started; the HTTP endpoints themselves are tested
 * in {@code ApiServerTest}.
 */
class ServeCommandTest {

    private record Captured(int exitCode, String stdout, String stderr) {
    }

    private static final WhoisClient OFFLINE_WHOIS = (server, query, timeoutMillis) -> {
        throw new IOException("network disabled in tests");
    };

    private static Captured runMain(String... args) {
        ByteArrayOutputStream outBytes = new ByteArrayOutputStream();
        ByteArrayOutputStream errBytes = new ByteArrayOutputStream();
        try (PrintStream out = new PrintStream(outBytes, true, StandardCharsets.UTF_8);
             PrintStream err = new PrintStream(errBytes, true, StandardCharsets.UTF_8)) {
            int code = Main.run(args, out, err, OFFLINE_WHOIS);
            return new Captured(code, outBytes.toString(StandardCharsets.UTF_8),
                    errBytes.toString(StandardCharsets.UTF_8));
        }
    }

    @Test
    void serveHelpDescribesOptionsWithoutRequiringScanInput() {
        Captured result = runMain("serve", "--help");

        assertEquals(0, result.exitCode());
        assertTrue(result.stdout().contains("phishnet serve"), result.stdout());
        assertTrue(result.stdout().contains("--port"), result.stdout());
        assertTrue(result.stdout().contains("8080"), result.stdout());
        assertFalse(result.stderr().contains("Missing required argument"), result.stderr());
    }

    @Test
    void mainHelpMentionsServeMode() {
        Captured result = runMain("--help");

        assertEquals(0, result.exitCode());
        assertTrue(result.stdout().contains("phishnet serve"), result.stdout());
    }

    @Test
    void outOfRangePortIsUsageError() {
        Captured result = runMain("serve", "--port", "70000");

        assertEquals(2, result.exitCode());
        assertTrue(result.stderr().contains("not a valid port"), result.stderr());
    }

    @Test
    void nonNumericPortIsUsageError() {
        Captured result = runMain("serve", "--port", "http");

        assertEquals(2, result.exitCode());
        assertTrue(result.stderr().contains("Error"), result.stderr());
    }

    @Test
    void scanOptionsAreNotAcceptedByServe() {
        Captured result = runMain("serve", "--url", "https://example.com");

        assertEquals(2, result.exitCode());
        assertTrue(result.stderr().contains("Unknown option"), result.stderr());
    }

    @Test
    void unreadableConfigFailsBeforeStartingServer(@TempDir Path tempDir) {
        Captured result = runMain("serve", "--port", "0", "--config", tempDir.resolve("missing.yaml").toString());

        assertEquals(1, result.exitCode());
        assertTrue(result.stderr().contains("could not load config"), result.stderr());
        assertFalse(result.stdout().contains("listening"), result.stdout());
    }

    @Test
    void scanModeStillRequiresInputWhenServeIsNotFirst() {
        // "serve" only switches modes as the first argument; anywhere else the normal
        // CLI parsing (and its required --url/--email/--batch group) applies unchanged.
        Captured result = runMain("--no-history", "serve");

        assertEquals(2, result.exitCode());
        assertTrue(result.stderr().contains("Error"), result.stderr());
    }
}
