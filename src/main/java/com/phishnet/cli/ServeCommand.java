package com.phishnet.cli;

import com.phishnet.analyzer.WhoisClient;
import com.phishnet.api.ApiServer;
import com.phishnet.api.ScanService;
import com.phishnet.model.PhishNetConfig;
import com.phishnet.util.ConfigLoader;
import picocli.CommandLine.Command;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Option;
import picocli.CommandLine.ParameterException;
import picocli.CommandLine.Spec;

import java.io.PrintStream;
import java.nio.file.Path;
import java.util.concurrent.Callable;

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
                + "(POST /api/scan/url, POST /api/scan/email, GET /api/health).",
        synopsisHeading = "%nUsage:%n",
        descriptionHeading = "%n",
        optionListHeading = "%nOptions:%n",
        footerHeading = "%nExamples:%n",
        footer = {
                "  phishnet serve",
                "  phishnet serve --port 9090 --no-whois"
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

    private final PrintStream out;
    private final PrintStream err;
    private final WhoisClient whoisClient;

    ServeCommand(PrintStream out, PrintStream err, WhoisClient whoisClient) {
        this.out = out;
        this.err = err;
        this.whoisClient = whoisClient;
    }

    @Override
    public Integer call() {
        if (port < 0 || port > 65535) {
            throw new ParameterException(spec.commandLine(),
                    "Invalid value for option '--port': " + port + " is not a valid port (0-65535)");
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

        // null = --no-whois, same convention as the CLI scan modes.
        ApiServer server = new ApiServer(new ScanService(config, noWhois ? null : whoisClient), err);
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
        return 0;
    }
}
