package com.phishnet.cli;

import com.phishnet.analyzer.DomainAgeChecker;
import com.phishnet.analyzer.UrlAnalyzer;
import com.phishnet.analyzer.WhoisClient;
import com.phishnet.batch.ParallelScanner;
import com.phishnet.batch.UrlScanner;
import com.phishnet.history.HistoryDatabase;
import com.phishnet.i18n.Messages;
import com.phishnet.model.PhishNetConfig;
import com.phishnet.queue.JobQueue;
import com.phishnet.queue.QueueException;
import com.phishnet.queue.QueueWorker;
import com.phishnet.queue.RedisJobQueue;
import com.phishnet.queue.RedisSettings;
import com.phishnet.queue.ScanJob;
import com.phishnet.scoring.RiskScorer;
import com.phishnet.util.ColorSupport;
import com.phishnet.util.ConfigLoader;
import picocli.CommandLine;
import picocli.CommandLine.ArgGroup;
import picocli.CommandLine.Command;
import picocli.CommandLine.Mixin;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Option;
import picocli.CommandLine.ParameterException;
import picocli.CommandLine.Spec;

import java.io.IOException;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;

/**
 * {@code phishnet queue produce|worker}: the optional distributed mode. {@code produce}
 * pushes URLs onto a Redis list; any number of {@code worker} processes, on any number
 * of machines, take them off and scan them. Like {@code serve}, {@link Main#run} hands
 * it the arguments after "queue", and nothing here runs - or needs Redis - otherwise.
 */
@Command(
        name = "phishnet " + Main.QUEUE_COMMAND,
        resourceBundle = Main.MESSAGES_BUNDLE,
        mixinStandardHelpOptions = true,
        versionProvider = Main.VersionProvider.class,
        sortOptions = false,
        descriptionHeading = "%n")
final class QueueCommand implements Callable<Integer> {

    static final String PASSWORD_ENV = "PHISHNET_REDIS_PASSWORD";
    static final String USERNAME_ENV = "PHISHNET_REDIS_USERNAME";

    /** Printed after a connection failure. */
    static String unreachableHint() {
        return Messages.text("queue.unreachableHint");
    }

    /** Connects to the queue; replaced in tests. */
    @FunctionalInterface
    interface Connector {
        JobQueue connect(RedisSettings settings) throws QueueException;
    }

    @Spec
    private CommandSpec spec;

    @Override
    public Integer call() {
        throw new ParameterException(spec.commandLine(), Messages.text("cli.missingCommand.two", "produce", "worker"));
    }

    /** Everything that touches the outside world, swappable for tests. */
    record Environment(PrintStream out, PrintStream err, Map<String, String> env, WhoisClient whoisClient,
                       Connector connector, Clock clock, boolean installShutdownHook) {
    }

    static CommandLine commandLine(PrintStream out, PrintStream err, WhoisClient whoisClient) {
        return commandLine(new Environment(out, err, System.getenv(), whoisClient, RedisJobQueue::connect,
                Clock.systemDefaultZone(), true));
    }

    static CommandLine commandLine(Environment environment) {
        CommandLine cmd = new CommandLine(new QueueCommand());
        cmd.addSubcommand("produce", new ProduceCommand(environment));
        cmd.addSubcommand("worker", new WorkerCommand(environment));
        return cmd;
    }

    /** Where the queue is - shared by both subcommands. */
    static final class RedisOptions {
        @Option(names = "--redis-host", paramLabel = "<host>", defaultValue = RedisSettings.DEFAULT_HOST)
        String host;

        @Option(names = "--redis-port", paramLabel = "<port>", defaultValue = "" + RedisSettings.DEFAULT_PORT)
        int port;

        @Option(names = "--redis-ssl")
        boolean ssl;

        @Option(names = "--queue", paramLabel = "<name>", defaultValue = RedisSettings.DEFAULT_QUEUE)
        String queue;

        RedisSettings settings(CommandSpec spec, Map<String, String> env) {
            if (port < 1 || port > 65535) {
                throw new ParameterException(spec.commandLine(),
                        Messages.text("cli.invalid.port", "--redis-port", port, "1-65535"));
            }
            if (queue.isBlank()) {
                throw new ParameterException(spec.commandLine(), Messages.text("cli.invalid.empty", "--queue"));
            }
            return new RedisSettings(host, port, env.get(USERNAME_ENV), env.get(PASSWORD_ENV), ssl, queue);
        }
    }

    // --- produce ------------------------------------------------------------------------

    @Command(
            name = "produce",
            mixinStandardHelpOptions = true,
            versionProvider = Main.VersionProvider.class,
            sortOptions = false,
            descriptionHeading = "%n")
    static final class ProduceCommand implements Callable<Integer> {

        @Spec
        CommandSpec spec;

        @Mixin
        RedisOptions redis = new RedisOptions();

        @Option(names = "--file", paramLabel = "<urls.txt>", required = true)
        String file;

        @Option(names = {"--quiet", "-q"})
        boolean quiet;

        private final Environment environment;

        ProduceCommand(Environment environment) {
            this.environment = environment;
        }

        @Override
        public Integer call() {
            RedisSettings settings = redis.settings(spec, environment.env());
            List<String> targets;
            try {
                targets = readTargets(Path.of(file));
            } catch (IOException e) {
                String reason = e instanceof NoSuchFileException ? Messages.text("cli.fileNotFound") : e.getMessage();
                environment.err().println(Messages.text("cli.error.read", file, reason));
                return 1;
            }
            if (targets.isEmpty()) {
                environment.out().println(quiet ? "0" : Messages.text("queue.nothingToQueue", file));
                return 0;
            }

            Instant now = environment.clock().instant();
            List<String> payloads = new ArrayList<>(targets.size());
            for (String target : targets) {
                payloads.add(ScanJob.create(target, now).toJson());
            }
            long waiting;
            try (JobQueue queue = environment.connector().connect(settings)) {
                waiting = queue.push(payloads);
            } catch (QueueException e) {
                environment.err().println(Messages.text("cli.error", e.getMessage()));
                if (!e.isFatal()) {
                    environment.err().println(unreachableHint());
                }
                return 1;
            }
            environment.out().println(quiet ? Integer.toString(payloads.size())
                    : Messages.text("queue.queued", payloads.size(), settings.describe(), waiting));
            return 0;
        }
    }

    /** Non-empty, non-comment lines - the same rules as {@code --batch}. */
    static List<String> readTargets(Path file) throws IOException {
        List<String> targets = new ArrayList<>();
        for (String line : Files.readAllLines(file)) {
            String target = line.trim();
            if (!target.isEmpty() && !target.startsWith("#")) {
                targets.add(target);
            }
        }
        return targets;
    }

    // --- worker -------------------------------------------------------------------------

    @Command(
            name = "worker",
            mixinStandardHelpOptions = true,
            versionProvider = Main.VersionProvider.class,
            sortOptions = false,
            descriptionHeading = "%n")
    static final class WorkerCommand implements Callable<Integer> {

        @Spec
        CommandSpec spec;

        @Mixin
        RedisOptions redis = new RedisOptions();

        @Option(names = "--threads", paramLabel = "<n>")
        Integer threads;

        @Option(names = "--retry")
        boolean retry;

        @Option(names = "--exit-when-empty")
        boolean exitWhenEmpty;

        @Option(names = "--no-whois")
        boolean noWhois;

        @Option(names = "--config", paramLabel = "<path>")
        String configPath;

        @Option(names = "--history-file", paramLabel = "<path>")
        String historyFile;

        @Option(names = "--no-history")
        boolean noHistory;

        @Option(names = "--history-db", paramLabel = "<path>")
        String historyDb;

        @Option(names = "--no-history-db")
        boolean noHistoryDb;

        @ArgGroup(exclusive = true, multiplicity = "0..1", heading = "%n")
        Verbosity verbosity = new Verbosity();

        static final class Verbosity {
            @Option(names = {"--verbose", "-v"})
            boolean verbose;

            @Option(names = {"--quiet", "-q"})
            boolean quiet;
        }

        @Option(names = "--no-color")
        boolean noColor;

        private final Environment environment;

        WorkerCommand(Environment environment) {
            this.environment = environment;
        }

        @Override
        public Integer call() throws InterruptedException {
            if (threads != null && (threads < 1 || threads > ParallelScanner.MAX_THREADS)) {
                throw new ParameterException(spec.commandLine(), Messages.text("cli.invalid.range", "--threads",
                        threads, 1, ParallelScanner.MAX_THREADS));
            }
            int threadCount = threads != null ? threads : ParallelScanner.defaultThreads();
            RedisSettings settings = redis.settings(spec, environment.env());
            PrintStream err = environment.err();

            PhishNetConfig config;
            try {
                config = configPath != null ? ConfigLoader.load(Path.of(configPath)) : ConfigLoader.loadDefault();
            } catch (RuntimeException e) {
                err.println(Messages.text("cli.error.config", e.getMessage()));
                return 1;
            }

            // A fresh DomainAgeChecker per job: its caches (including "this server failed once,
            // don't retry it") are meant for one run, not for a worker that runs for days.
            WhoisClient whois = environment.whoisClient();
            UrlScanner scanner = new UrlScanner(new UrlAnalyzer(config),
                    noWhois ? UrlScanner.SKIP_DOMAIN_AGE
                            : analysis -> new DomainAgeChecker(whois).check(analysis.components()),
                    new RiskScorer(config));

            HistoryWriter csv = new HistoryWriter(
                    historyFile != null ? Path.of(historyFile) : Path.of("phishnet-history.csv"), !noHistory, err);
            HistoryDatabase database = new HistoryDatabase(
                    historyDb != null ? Path.of(historyDb) : HistoryDatabase.defaultPath(), !noHistoryDb, err);
            QueueWorker.Recorder recorder = result -> {
                csv.record(result.url(), HistoryWriter.TargetType.URL, result.score(), result.domainAge());
                database.recordUrl(result.url(), result.analysis().components(), result.score(), result.domainAge());
            };

            OutputLevel level = verbosity.quiet ? OutputLevel.QUIET
                    : verbosity.verbose ? OutputLevel.VERBOSE : OutputLevel.NORMAL;
            QueueWorkerReporter reporter = new QueueWorkerReporter(environment.out(), err, level,
                    ColorSupport.isEnabled(noColor), environment.clock());
            QueueWorker worker = new QueueWorker(() -> environment.connector().connect(settings), scanner, recorder,
                    reporter, threadCount, retry, exitWhenEmpty);

            try {
                worker.checkConnection();
            } catch (QueueException e) {
                if (!retry || e.isFatal()) {
                    reporter.fatal(e);
                    return 1;
                }
                err.println(Messages.text("queue.retrying", e.getMessage()));
            }

            reporter.header(Messages.text("queue.workerHeader", threadCount, settings.describe()) + " "
                    + Messages.text(exitWhenEmpty ? "queue.stopsWhenEmpty" : "cli.pressCtrlC"));

            Thread hook = new Thread(worker::stop, "phishnet-queue-worker-shutdown");
            if (environment.installShutdownHook()) {
                Runtime.getRuntime().addShutdownHook(hook);
            }
            QueueWorker.Exit exit;
            try {
                exit = worker.run();
            } finally {
                if (environment.installShutdownHook()) {
                    try {
                        Runtime.getRuntime().removeShutdownHook(hook);
                    } catch (IllegalStateException alreadyShuttingDown) {
                        // the hook is what stopped the worker
                    }
                }
            }
            reporter.stopped();
            return exit == QueueWorker.Exit.FATAL_ERROR ? 1 : 0;
        }
    }
}
