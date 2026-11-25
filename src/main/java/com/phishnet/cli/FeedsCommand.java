package com.phishnet.cli;

import com.phishnet.feeds.FeedRefreshResult;
import com.phishnet.feeds.FeedStatus;
import com.phishnet.feeds.ThreatFeedService;
import com.phishnet.feeds.ThreatFeedSettings;
import com.phishnet.i18n.Messages;
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
        resourceBundle = Main.MESSAGES_BUNDLE,
        mixinStandardHelpOptions = true,
        versionProvider = Main.VersionProvider.class,
        sortOptions = false,
        descriptionHeading = "%n")
final class FeedsCommand implements Callable<Integer> {

    @Spec
    private CommandSpec spec;

    @Override
    public Integer call() {
        throw new ParameterException(spec.commandLine(), Messages.text("cli.missingCommand.two", "update", "status"));
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

        @Option(names = "--config", paramLabel = "<path>")
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
                err.println(Messages.text("cli.error.config", e.getMessage()));
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
            descriptionHeading = "%n")
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
            out.println(Messages.text("feeds.updating", service.cache().directory()));
            List<FeedRefreshResult> results = service.refreshAll();
            boolean failed = false;
            for (FeedRefreshResult result : results) {
                String name = result.source().displayName() + ":";
                switch (result.outcome()) {
                    case UPDATED -> out.println(String.format("  %-11s %s", name,
                            Messages.text("feeds.result.updated", FeedStatus.entryCount(result.entries()))));
                    case SKIPPED -> out.println(String.format("  %-11s %s", name,
                            Messages.text("feeds.result.skipped", result.message())));
                    case FAILED -> {
                        failed = true;
                        out.println(String.format("  %-11s %s", name, Messages.text("feeds.result.failed", result.message())));
                    }
                }
            }
            if (failed) {
                err.println(Messages.text("feeds.someFailed"));
            }
            return failed ? 1 : 0;
        }
    }

    @Command(
            name = "status",
            mixinStandardHelpOptions = true,
            versionProvider = Main.VersionProvider.class,
            sortOptions = false,
            descriptionHeading = "%n")
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
            out.println(Messages.text("feeds.status.cacheDirectory", service.cache().directory()));
            out.println(Messages.text("feeds.status.refreshInterval", formatDuration(service.settings().refreshInterval())));
            for (FeedStatus status : service.status()) {
                out.println();
                out.println(status.source().displayName());
                out.println("  " + Messages.text("feeds.status.state", stateLine(status)));
                if (status.state().available() || status.state() == FeedStatus.State.MISSING) {
                    out.println("  " + Messages.text("feeds.status.lastRefresh", status.refreshedAt() == null
                            ? Messages.text("feeds.status.never")
                            : Messages.text("feeds.status.ago", status.refreshedAt(),
                                    formatDuration(Duration.between(status.refreshedAt(), now)))));
                    out.println("  " + Messages.text("feeds.status.entries", String.format("%,d", status.entries())));
                }
                if (status.lastError() != null) {
                    out.println("  " + Messages.text("feeds.status.lastError", status.lastError()));
                }
            }
            return 0;
        }

        private static String stateLine(FeedStatus status) {
            return Messages.text("feeds.state." + status.state().name(), status.detail());
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
        return Messages.current().plural("duration." + unit, count);
    }
}
