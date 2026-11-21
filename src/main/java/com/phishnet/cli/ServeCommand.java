package com.phishnet.cli;

import com.phishnet.analyzer.WhoisClient;
import com.phishnet.api.ApiKeyStore;
import com.phishnet.api.ApiServer;
import com.phishnet.api.ScanService;
import com.phishnet.feeds.ThreatFeedService;
import com.phishnet.feeds.ThreatFeedSettings;
import com.phishnet.history.HistoryDatabase;
import com.phishnet.model.PhishNetConfig;
import com.phishnet.util.ConfigLoader;
import picocli.CommandLine.Command;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Option;
import picocli.CommandLine.ParameterException;
import picocli.CommandLine.Spec;

import java.io.IOException;
import java.io.PrintStream;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.function.Function;

/**
 * {@code phishnet serve}: runs the REST API ({@link ApiServer}) instead of a
 * one-off scan. {@link Main#run} hands it the arguments after "serve", so a
 * plain {@code phishnet --url ...} run never touches any of this.
 *
 * {@link #call()} returns as soon as the server is listening; Jetty's
 * (non-daemon) threads then keep the process alive until it is stopped
 * with Ctrl+C / SIGTERM, which shuts the server down cleanly.
 */
@Command(
        name = "phishnet " + Main.SERVE_COMMAND,
        mixinStandardHelpOptions = true,
        versionProvider = Main.VersionProvider.class,
        sortOptions = false,
        description = "Start an HTTP server exposing the scanner as a JSON REST API "
                + "(POST /api/scan/url, POST /api/scan/email, GET /api/health), plus read-only history and "
                + "feed status endpoints and, when it has been built, the web dashboard on the same port.",
        synopsisHeading = "%nUsage:%n",
        descriptionHeading = "%n",
        optionListHeading = "%nOptions:%n",
        footerHeading = "%nExamples:%n",
        footer = {
                "  phishnet serve",
                "  phishnet serve --port 9090 --no-whois",
                "  phishnet serve --dashboard dashboard/dist",
                "  phishnet serve --regenerate-key      (replace the API key)",
                "  phishnet serve --no-auth             (local development only: no API key)"
        }
)
final class ServeCommand implements Callable<Integer> {

    @Spec
    private CommandSpec spec;

    @Option(names = "--port", paramLabel = "<port>", defaultValue = "" + ApiServer.DEFAULT_PORT,
            description = "TCP port to listen on (default: ${DEFAULT-VALUE}; 0 picks a free port)")
    private int port;

    @Option(names = "--config", paramLabel = "<path>",
            description = "Use a custom YAML config instead of the bundled default")
    private String configPath;

    @Option(names = "--no-whois",
            description = "Skip the live WHOIS domain-age lookup for URL scans")
    private boolean noWhois;

    @Option(names = "--history-db", paramLabel = "<path>",
            description = "Record API scans in this SQLite database "
                    + "(default: ~/.phishnet/phishnet-history.db; query it with: phishnet history)")
    private String databaseFile;

    @Option(names = "--no-history-db",
            description = "Do not record API scans in the scan history database")
    private boolean noHistoryDb;

    @Option(names = "--dashboard", paramLabel = "<dir>",
            description = "Serve the built web dashboard from this directory (default: $"
                    + DASHBOARD_DIR_ENV + ", else ./dashboard/dist, else a dashboard/ folder next to the jar - "
                    + "the first that contains an index.html)")
    private String dashboardDir;

    @Option(names = "--no-dashboard",
            description = "Serve the REST API only, without the web dashboard")
    private boolean noDashboard;

    @Option(names = "--api-key-file", paramLabel = "<path>",
            description = "Where the API key is kept (default: ~/.phishnet/api-key; created with a new random "
                    + "key on first run). $" + ApiKeyStore.KEY_ENV + ", when set, is used instead.")
    private String apiKeyFile;

    @Option(names = "--regenerate-key",
            description = "Replace the API key with a new random one before starting (printed once). "
                    + "The old key stops working; give the new one to every client.")
    private boolean regenerateKey;

    @Option(names = "--rate-limit", paramLabel = "<requests-per-minute>",
            description = "Scan requests each client IP may make per minute before getting 429 Too Many Requests "
                    + "(default: api.rateLimitPerMinute from the config, 60; 0 turns it off)")
    private Integer rateLimit;

    @Option(names = "--no-auth",
            description = "Don't require an API key: anyone who can reach this port can scan and read the scan "
                    + "history. Meant for local development only.")
    private boolean noAuth;

    /** Environment variable naming the built dashboard directory (set in the Docker image). */
    static final String DASHBOARD_DIR_ENV = "PHISHNET_DASHBOARD_DIR";

    private final PrintStream out;
    private final PrintStream err;
    private final WhoisClient whoisClient;
    private final Function<ThreatFeedSettings, ThreatFeedService> threatFeeds;
    private final Map<String, String> environment;

    /**
     * @param threatFeeds builds the feed service behind {@code GET /api/feeds/status}
     *                    ({@link ThreatFeedService#live} outside tests); only its cache is read
     */
    ServeCommand(PrintStream out, PrintStream err, WhoisClient whoisClient,
                 Function<ThreatFeedSettings, ThreatFeedService> threatFeeds) {
        this(out, err, whoisClient, threatFeeds, System.getenv());
    }

    /** Same, with the environment ({@value ApiKeyStore#KEY_ENV}) swapped out for tests. */
    ServeCommand(PrintStream out, PrintStream err, WhoisClient whoisClient,
                 Function<ThreatFeedSettings, ThreatFeedService> threatFeeds, Map<String, String> environment) {
        this.out = out;
        this.err = err;
        this.whoisClient = whoisClient;
        this.threatFeeds = threatFeeds;
        this.environment = environment;
    }

    @Override
    public Integer call() {
        if (port < 0 || port > 65535) {
            throw new ParameterException(spec.commandLine(),
                    "Invalid value for option '--port': " + port + " is not a valid port (0-65535)");
        }
        if (rateLimit != null && rateLimit < 0) {
            throw new ParameterException(spec.commandLine(),
                    "Invalid value for option '--rate-limit': " + rateLimit + " (must be 0 or more)");
        }
        if (noAuth && regenerateKey) {
            throw new ParameterException(spec.commandLine(),
                    "--regenerate-key and --no-auth can't be combined: with --no-auth no key is used");
        }
        String envKey = environment.get(ApiKeyStore.KEY_ENV);
        if (regenerateKey && envKey != null && !envKey.isBlank()) {
            err.println("Error: --regenerate-key can't replace a key set through $" + ApiKeyStore.KEY_ENV
                    + "; set that variable to a new value instead");
            return 1;
        }

        PhishNetConfig config;
        try {
            config = configPath != null
                    ? ConfigLoader.load(Path.of(configPath))
                    : ConfigLoader.loadDefault();
        } catch (RuntimeException e) {
            err.println("Error: could not load config: " + e.getMessage());
            return 1;
        }

        Path dashboard = null;
        if (!noDashboard) {
            if (dashboardDir != null) {
                dashboard = Path.of(dashboardDir);
                if (!ApiServer.isDashboardDirectory(dashboard)) {
                    err.println("Error: --dashboard " + dashboardDir + " has no index.html "
                            + "(build the dashboard with: cd dashboard && npm install && npm run build)");
                    return 1;
                }
            } else {
                dashboard = findDashboard(System.getenv(DASHBOARD_DIR_ENV), Path.of(""), jarDirectory());
            }
        }

        // Loaded only now, after every option and the config have been checked, so a
        // mistyped command line never creates a key file. null = --no-auth.
        ApiKeyStore.LoadedKey apiKey = null;
        if (!noAuth) {
            Path keyFile = apiKeyFile != null ? Path.of(apiKeyFile) : ApiKeyStore.defaultPath();
            try {
                apiKey = regenerateKey ? ApiKeyStore.regenerate(keyFile) : ApiKeyStore.loadOrCreate(keyFile, envKey);
            } catch (IOException | IllegalArgumentException e) {
                err.println("Error: could not " + (regenerateKey ? "replace" : "load") + " the API key: "
                        + e.getMessage());
                return 1;
            }
        }

        // null = --no-whois / --no-history-db, same convention as the CLI scan modes.
        // The database is only created on the first recorded scan.
        Path historyFile = databaseFile != null ? Path.of(databaseFile) : HistoryDatabase.defaultPath();
        HistoryDatabase history = noHistoryDb ? null : new HistoryDatabase(historyFile, true, err);
        // The dashboard's history endpoints only read, like `phishnet history`, so they work
        // even with --no-history-db (which only stops this server from recording scans).
        HistoryDatabase historyReader = new HistoryDatabase(historyFile, false, err);
        ApiServer server = new ApiServer(new ScanService(config, noWhois ? null : whoisClient, history), err)
                .withHistory(historyReader)
                .withFeeds(threatFeeds.apply(config.threatFeeds().withEnvironment(System.getenv())))
                .withDashboard(dashboard)
                .withApiKey(apiKey == null ? null : apiKey.key())
                .withRateLimit(effectiveRateLimit(config));
        try {
            server.start(port);
        } catch (RuntimeException e) {
            err.println("Error: could not start API server on port " + port + ": " + e.getMessage());
            return 1;
        }
        Runtime.getRuntime().addShutdownHook(new Thread(server::stop, "phishnet-api-shutdown"));

        out.println("PhishNet API listening on http://localhost:" + server.port() + " (Ctrl+C to stop)");
        out.println("  GET  /api/health");
        out.println("  POST /api/scan/url");
        out.println("  POST /api/scan/email");
        out.println("  GET  /api/history");
        out.println("  GET  /api/history/stats");
        out.println("  GET  /api/feeds/status");
        out.println("  GET  /api/auth/check");
        if (history != null) {
            out.println("Recording scans to " + history.file());
        }
        printApiKey(apiKey, server.port());
        int limit = effectiveRateLimit(config);
        out.println(limit > 0
                ? "Rate limit: " + limit + " scan requests per minute per client"
                : "Rate limit: off");
        if (dashboard != null) {
            out.println("Web dashboard: http://localhost:" + server.port() + "/ (from " + dashboard.toAbsolutePath()
                    + ")");
        } else if (!noDashboard) {
            out.println("Web dashboard: not found, serving the API only "
                    + "(build it with: cd dashboard && npm install && npm run build)");
        }
        return 0;
    }

    /** --rate-limit if given, else the config's api.rateLimitPerMinute. */
    private int effectiveRateLimit(PhishNetConfig config) {
        return rateLimit != null ? rateLimit : config.api().rateLimitPerMinute();
    }

    /** Shows a newly generated key once, in full; otherwise only says where the key comes from. */
    private void printApiKey(ApiKeyStore.LoadedKey apiKey, int listeningPort) {
        if (apiKey == null) {
            err.println("Warning: API authentication is disabled (--no-auth): anyone who can reach port "
                    + listeningPort + " can scan and read the scan history.");
            return;
        }
        switch (apiKey.source()) {
            case CREATED, REGENERATED -> {
                out.println();
                out.println((apiKey.source() == ApiKeyStore.Source.REGENERATED
                        ? "Replaced the API key with a new one" : "Generated a new API key")
                        + " and saved it to " + apiKey.file().toAbsolutePath() + ":");
                out.println();
                out.println("    " + apiKey.key());
                out.println();
                out.println("Clients (the browser extension, the web dashboard, scripts) must send it in the "
                        + ApiServer.API_KEY_HEADER + " header.");
                out.println("It is shown only this once; to see it again, read that file. "
                        + "To replace it: phishnet serve --regenerate-key");
                out.println();
            }
            case FILE -> out.println("API key required (" + ApiServer.API_KEY_HEADER + " header): from "
                    + apiKey.file().toAbsolutePath());
            case ENVIRONMENT -> out.println("API key required (" + ApiServer.API_KEY_HEADER + " header): from $"
                    + ApiKeyStore.KEY_ENV);
        }
    }

    /**
     * The built dashboard to serve when {@code --dashboard} isn't given: the first of
     * {@code envValue} ({@value #DASHBOARD_DIR_ENV}), {@code workingDir/dashboard/dist}
     * (a source checkout), and {@code jarDir/dashboard} (an unpacked release) that
     * contains an index.html; {@code null} if none does.
     */
    static Path findDashboard(String envValue, Path workingDir, Path jarDir) {
        List<Path> candidates = new ArrayList<>();
        if (envValue != null && !envValue.isBlank()) {
            candidates.add(Path.of(envValue.trim()));
        }
        candidates.add(workingDir.resolve("dashboard").resolve("dist"));
        if (jarDir != null) {
            candidates.add(jarDir.resolve("dashboard"));
        }
        for (Path candidate : candidates) {
            if (ApiServer.isDashboardDirectory(candidate)) {
                return candidate;
            }
        }
        return null;
    }

    /** The directory holding the running jar, or {@code null} when not run from a jar (IDE, tests). */
    private static Path jarDirectory() {
        try {
            Path location = Path.of(ServeCommand.class.getProtectionDomain().getCodeSource().getLocation().toURI());
            return location.toString().endsWith(".jar") ? location.toAbsolutePath().getParent() : null;
        } catch (Exception e) {
            return null;
        }
    }
}
