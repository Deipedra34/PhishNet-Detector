package com.phishnet.cli;

import com.phishnet.analyzer.WhoisClient;
import com.phishnet.api.ApiKeyStore;
import com.phishnet.api.ApiServer;
import com.phishnet.api.ScanService;
import com.phishnet.feeds.ThreatFeedService;
import com.phishnet.feeds.ThreatFeedSettings;
import com.phishnet.history.HistoryDatabase;
import com.phishnet.i18n.Messages;
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
        resourceBundle = Main.MESSAGES_BUNDLE,
        mixinStandardHelpOptions = true,
        versionProvider = Main.VersionProvider.class,
        sortOptions = false,
        descriptionHeading = "%n")
final class ServeCommand implements Callable<Integer> {

    @Spec
    private CommandSpec spec;

    @Option(names = "--port", paramLabel = "<port>", defaultValue = "" + ApiServer.DEFAULT_PORT)
    private int port;

    @Option(names = "--config", paramLabel = "<path>")
    private String configPath;

    @Option(names = "--no-whois")
    private boolean noWhois;

    @Option(names = "--history-db", paramLabel = "<path>")
    private String databaseFile;

    @Option(names = "--no-history-db")
    private boolean noHistoryDb;

    @Option(names = "--dashboard", paramLabel = "<dir>")
    private String dashboardDir;

    @Option(names = "--no-dashboard")
    private boolean noDashboard;

    @Option(names = "--api-key-file", paramLabel = "<path>")
    private String apiKeyFile;

    @Option(names = "--regenerate-key")
    private boolean regenerateKey;

    @Option(names = "--rate-limit", paramLabel = "<requests-per-minute>")
    private Integer rateLimit;

    @Option(names = "--no-auth")
    private boolean noAuth;

    /** Environment variable naming the built dashboard directory (set in the Docker image). */
    static final String DASHBOARD_DIR_ENV = "PHISHNET_DASHBOARD_DIR";

    private final PrintStream out;
    private final PrintStream err;
    private final WhoisClient whoisClient;
    private final Function<ThreatFeedSettings, ThreatFeedService> threatFeeds;
    private final Map<String, String> environment;
    /** The running server once {@link #call()} has started it, so tests can stop it. */
    private ApiServer startedServer;

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
                    Messages.text("cli.invalid.port", "--port", port, "0-65535"));
        }
        if (rateLimit != null && rateLimit < 0) {
            throw new ParameterException(spec.commandLine(),
                    Messages.text("cli.invalid.nonNegative", "--rate-limit", rateLimit));
        }
        if (noAuth && regenerateKey) {
            throw new ParameterException(spec.commandLine(),
                    Messages.text("serve.error.regenerateNoAuth"));
        }
        String envKey = environment.get(ApiKeyStore.KEY_ENV);
        if (regenerateKey && envKey != null && !envKey.isBlank()) {
            err.println(Messages.text("serve.error.regenerateEnv", ApiKeyStore.KEY_ENV));
            return 1;
        }

        PhishNetConfig config;
        try {
            config = configPath != null
                    ? ConfigLoader.load(Path.of(configPath))
                    : ConfigLoader.loadDefault();
        } catch (RuntimeException e) {
            err.println(Messages.text("cli.error.config", e.getMessage()));
            return 1;
        }

        Path dashboard = null;
        if (!noDashboard) {
            if (dashboardDir != null) {
                dashboard = Path.of(dashboardDir);
                if (!ApiServer.isDashboardDirectory(dashboard)) {
                    err.println(Messages.text("serve.error.noIndex", dashboardDir));
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
                err.println(Messages.text(regenerateKey ? "serve.error.keyReplace" : "serve.error.keyLoad",
                        e.getMessage()));
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
            err.println(Messages.text("serve.error.start", port, e.getMessage()));
            return 1;
        }
        Runtime.getRuntime().addShutdownHook(new Thread(server::stop, "phishnet-api-shutdown"));
        startedServer = server;

        out.println(Messages.text("serve.listening", server.port()));
        out.println("  GET  /api/health");
        out.println("  POST /api/scan/url");
        out.println("  POST /api/scan/email");
        out.println("  GET  /api/history");
        out.println("  GET  /api/history/stats");
        out.println("  GET  /api/feeds/status");
        out.println("  GET  /api/auth/check");
        if (history != null) {
            out.println(Messages.text("serve.recording", history.file()));
        }
        printApiKey(apiKey, server.port());
        int limit = effectiveRateLimit(config);
        out.println(limit > 0
                ? Messages.text("serve.rateLimit", limit)
                : Messages.text("serve.rateLimit.off"));
        if (dashboard != null) {
            out.println(Messages.text("serve.dashboard", server.port(), dashboard.toAbsolutePath()));
        } else if (!noDashboard) {
            out.println(Messages.text("serve.dashboard.missing"));
        }
        return 0;
    }

    /** The server {@link #call()} started, or {@code null} if it didn't start one (for tests). */
    ApiServer startedServer() {
        return startedServer;
    }

    /** --rate-limit if given, else the config's api.rateLimitPerMinute. */
    private int effectiveRateLimit(PhishNetConfig config) {
        return rateLimit != null ? rateLimit : config.api().rateLimitPerMinute();
    }

    /** Shows a newly generated key once, in full; otherwise only says where the key comes from. */
    private void printApiKey(ApiKeyStore.LoadedKey apiKey, int listeningPort) {
        if (apiKey == null) {
            err.println(Messages.text("serve.noAuthWarning", listeningPort));
            return;
        }
        switch (apiKey.source()) {
            case CREATED, REGENERATED -> {
                out.println();
                out.println(Messages.text(apiKey.source() == ApiKeyStore.Source.REGENERATED
                        ? "serve.key.replaced" : "serve.key.generated", apiKey.file().toAbsolutePath()));
                out.println();
                out.println("    " + apiKey.key());
                out.println();
                out.println(Messages.text("serve.key.clients", ApiServer.API_KEY_HEADER));
                out.println(Messages.text("serve.key.shownOnce"));
                out.println();
            }
            case FILE -> out.println(Messages.text("serve.key.required", ApiServer.API_KEY_HEADER,
                    apiKey.file().toAbsolutePath()));
            case ENVIRONMENT -> out.println(Messages.text("serve.key.required", ApiServer.API_KEY_HEADER,
                    "$" + ApiKeyStore.KEY_ENV));
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
