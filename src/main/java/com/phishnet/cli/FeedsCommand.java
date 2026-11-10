package com.phishnet.cli;

import com.phishnet.feeds.FeedRefreshResult;
import com.phishnet.feeds.FeedStatus;
import com.phishnet.feeds.ThreatFeedService;
import com.phishnet.feeds.ThreatFeedSettings;
import com.phishnet.model.PhishNetConfig;
import com.phishnet.util.ConfigLoader;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Option;
import picocli.CommandLine.ParameterException;
import picocli.CommandLine.Spec;

import java.io.PrintStream;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.function.Function;

/**
 * {@code phishnet feeds update|status}: manages the cached threat intelligence
 * feeds (OpenPhish, PhishTank) that scans check URLs against. Like
 * {@code history} and {@code model}, {@link Main#run} hands it the arguments
 * after "feeds", so normal scan parsing is untouched.
 */
@Command(
        name = "phishnet " + Main.FEEDS_COMMAND,
        mixinStandardHelpOptions = true,
        versionProvider = Main.VersionProvider.class,
        sortOptions = false,
        synopsisSubcommandLabel = "COMMAND",
        description = "Download or inspect the threat intelligence feeds of known phishing URLs "
                + "(OpenPhish, and PhishTank when an API key is set). Scans refresh stale feeds on their own; "
                + "--no-threat-feeds turns the feeds off for a scan.",
        synopsisHeading = "%nUsage:%n",
        descriptionHeading = "%n",
        optionListHeading = "%nOptions:%n",
        commandListHeading = "%nCommands:%n",
        footerHeading = "%nExamples:%n",
        footer = {
                "  phishnet feeds update",
                "  phishnet feeds status",
                "  PHISHNET_PHISHTANK_API_KEY=<key> phishnet feeds update"
        }
)
final class FeedsCommand implements Callable<Integer> {

    @Spec
    private CommandSpec spec;

    @Override
    public Integer call() {
        throw new ParameterException(spec.commandLine(), "Missing required command: update or status");
    }

    /**
     * The {@code feeds} command with its subcommands wired to the given streams.
     *
     * @param services builds the feed service from the config's feed settings
     *                 ({@link ThreatFeedService#live} outside tests)
     */
    static CommandLine commandLine(PrintStream out, PrintStream err,
                                   Function<ThreatFeedSettings, ThreatFeedService> services) {
        CommandLine cmd = new CommandLine(new FeedsCommand());
        cmd.addSubcommand("update", new UpdateCommand(out, err, services));
        cmd.addSubcommand("status", new StatusCommand(out, err, services));
        return cmd;
    }

    /** The {@code --config} option and service setup shared by both subcommands. */
    abstract static class FeedServiceCommand implements Callable<Integer> {

        @Option(names = "--config", paramLabel = "<path>",
                description = "Read the threatFeeds settings from this YAML config instead of the bundled default")
        String configPath;

        final PrintStream out;
        final PrintStream err;
        private final Function<ThreatFeedSettings, ThreatFeedService> services;

        FeedServiceCommand(PrintStream out, PrintStream err,
                           Function<ThreatFeedSettings, ThreatFeedService> services) {
            this.out = out;
            this.err = err;
            this.services = services;
        }

        /** The feed service for the configured settings, or {@code null} (after printing why) if the config is bad. */
        ThreatFeedService service() {
            PhishNetConfig config;
            try {
                config = configPath != null ? ConfigLoader.load(Path.of(configPath)) : ConfigLoader.loadDefault();
            } catch (RuntimeException e) {
                err.println("Error: could not load config: " + e.getMessage());
                return null;
            }
            return services.apply(config.threatFeeds().withEnvironment(System.getenv()));
        }
    }

    @Command(
            name = "update",
            mixinStandardHelpOptions = true,
            versionProvider = Main.VersionProvider.class,
            sortOptions = false,
            description = "Download every enabled feed now and replace its cached copy, however fresh it is. "
                    + "A feed that fails to download keeps its previous cached copy. "
                    + "Exits 1 if any feed failed.",
            synopsisHeading = "%nUsage:%n",
            descriptionHeading = "%n",
            optionListHeading = "%nOptions:%n"
    )
    static final class UpdateCommand extends FeedServiceCommand {

        UpdateCommand(PrintStream out, PrintStream err, Function<ThreatFeedSettings, ThreatFeedService> services) {
            super(out, err, services);
        }

        @Override
        public Integer call() {
            ThreatFeedService service = service();
            if (service == null) {
                return 1;
            }
            out.println("Updating threat feeds in " + service.cache().directory() + " ...");
            List<FeedRefreshResult> results = service.refreshAll();
            boolean failed = false;
            for (FeedRefreshResult result : results) {
                String name = result.source().displayName() + ":";
                switch (result.outcome()) {
                    case UPDATED -> out.println(String.format("  %-11s updated, %s", name,
                            FeedStatus.entryCount(result.entries())));
                    case SKIPPED -> out.println(String.format("  %-11s skipped (%s)", name, result.message()));
                    case FAILED -> {
                        failed = true;
                        out.println(String.format("  %-11s FAILED: %s", name, result.message()));
                    }
                }
            }
            if (failed) {
                err.println("Some feeds could not be downloaded; scans keep using their previous cached copy, "
                        + "if any.");
            }
            return failed ? 1 : 0;
        }
    }

    @Command(
            name = "status",
            mixinStandardHelpOptions = true,
            versionProvider = Main.VersionProvider.class,
            sortOptions = false,
            description = "Show each feed's cached copy: whether it's fresh, stale, or missing, when it was "
                    + "last refreshed, and how many entries it has. Reads the cache only; never downloads.",
            synopsisHeading = "%nUsage:%n",
            descriptionHeading = "%n",
            optionListHeading = "%nOptions:%n"
    )
    static final class StatusCommand extends FeedServiceCommand {

        StatusCommand(PrintStream out, PrintStream err, Function<ThreatFeedSettings, ThreatFeedService> services) {
            super(out, err, services);
        }

        @Override
        public Integer call() {
            ThreatFeedService service = service();
            if (service == null) {
                return 1;
            }
            Instant now = service.clock().instant();
            out.println("Cache directory:  " + service.cache().directory());
            out.println("Refresh interval: " + formatDuration(service.settings().refreshInterval()));
            for (FeedStatus status : service.status()) {
                out.println();
                out.println(status.source().displayName());
                out.println("  Status:       " + stateLine(status));
                if (status.state().available() || status.state() == FeedStatus.State.MISSING) {
                    out.println("  Last refresh: " + (status.refreshedAt() == null ? "never"
                            : status.refreshedAt() + " (" + formatDuration(Duration.between(status.refreshedAt(), now))
                            + " ago)"));
                    out.println(String.format("  Entries:      %,d", status.entries()));
                }
                if (status.lastError() != null) {
                    out.println("  Last error:   " + status.lastError());
                }
            }
            return 0;
        }

        private static String stateLine(FeedStatus status) {
            return switch (status.state()) {
                case FRESH -> "fresh (cached and available to scans)";
                case STALE -> "stale (cached copy still used by scans; refreshed on the next scan or "
                        + "`phishnet feeds update`)";
                case MISSING -> "missing (nothing cached yet, so scans skip this feed; run `phishnet feeds update`)";
                case DISABLED -> "disabled in the config";
                case NOT_CONFIGURED -> "not configured: " + status.detail();
                case OFF -> "off: " + status.detail();
            };
        }
    }

    /** "45 seconds", "1 minute", "3 hours", "2 days": the largest whole unit. */
    static String formatDuration(Duration duration) {
        long seconds = Math.max(0, duration.toSeconds());
        if (seconds < 60) {
            return plural(seconds, "second");
        }
        if (seconds < 3600) {
            return plural(seconds / 60, "minute");
        }
        if (seconds < 86_400) {
            return plural(seconds / 3600, "hour");
        }
        return plural(seconds / 86_400, "day");
    }

    private static String plural(long count, String unit) {
        return count + " " + unit + (count == 1 ? "" : "s");
    }
}
