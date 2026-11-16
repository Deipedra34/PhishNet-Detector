package com.phishnet.cli;

import com.phishnet.analyzer.WhoisClient;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
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

    // --- web dashboard ------------------------------------------------------------

    private static Path builtDashboard(Path dir) throws IOException {
        Files.createDirectories(dir);
        Files.writeString(dir.resolve("index.html"), "<!doctype html>");
        return dir;
    }

    @Test
    void dashboardDirectoryFromEnvironmentComesFirst(@TempDir Path tempDir) throws IOException {
        Path fromEnv = builtDashboard(tempDir.resolve("env"));
        builtDashboard(tempDir.resolve("cwd").resolve("dashboard").resolve("dist"));

        assertEquals(fromEnv, ServeCommand.findDashboard(fromEnv.toString(), tempDir.resolve("cwd"), null));
    }

    @Test
    void dashboardFallsBackToSourceCheckoutThenJarDirectory(@TempDir Path tempDir) throws IOException {
        Path checkout = builtDashboard(tempDir.resolve("cwd").resolve("dashboard").resolve("dist"));
        Path besideJar = builtDashboard(tempDir.resolve("jar").resolve("dashboard"));

        // An env var pointing at nothing usable is skipped.
        assertEquals(checkout, ServeCommand.findDashboard(tempDir.resolve("missing").toString(),
                tempDir.resolve("cwd"), tempDir.resolve("jar")));
        assertEquals(besideJar, ServeCommand.findDashboard(null, tempDir.resolve("elsewhere"), tempDir.resolve("jar")));
    }

    @Test
    void noBuiltDashboardMeansApiOnly(@TempDir Path tempDir) throws IOException {
        // A directory without index.html (e.g. built but then cleaned) doesn't count.
        Files.createDirectories(tempDir.resolve("dashboard").resolve("dist"));

        assertNull(ServeCommand.findDashboard("", tempDir, null));
    }

    @Test
    void explicitDashboardWithoutIndexFailsBeforeStartingServer(@TempDir Path tempDir) {
        Captured result = runMain("serve", "--port", "0", "--no-history-db",
                "--dashboard", tempDir.resolve("nothing-here").toString());

        assertEquals(1, result.exitCode());
        assertTrue(result.stderr().contains("has no index.html"), result.stderr());
        assertFalse(result.stdout().contains("listening"), result.stdout());
    }

    @Test
    void serveHelpDescribesDashboardOptions() {
        Captured result = runMain("serve", "--help");

        assertTrue(result.stdout().contains("--dashboard"), result.stdout());
        assertTrue(result.stdout().contains("--no-dashboard"), result.stdout());
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
