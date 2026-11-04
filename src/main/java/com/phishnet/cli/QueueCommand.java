package com.phishnet.cli;

import com.phishnet.analyzer.DomainAgeChecker;
import com.phishnet.analyzer.UrlAnalyzer;
import com.phishnet.analyzer.WhoisClient;
import com.phishnet.batch.ParallelScanner;
import com.phishnet.batch.UrlScanner;
import com.phishnet.history.HistoryDatabase;
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
        mixinStandardHelpOptions = true,
        versionProvider = Main.VersionProvider.class,
        sortOptions = false,
        synopsisSubcommandLabel = "COMMAND",
        description = "Distributed scanning through a shared Redis queue: 'produce' queues URLs from a file, "
                + "'worker' scans queued URLs. Run as many workers, on as many machines, as you like.",
        synopsisHeading = "%nUsage:%n",
        descriptionHeading = "%n",
        optionListHeading = "%nOptions:%n",
        commandListHeading = "%nCommands:%n",
        footerHeading = "%nExamples:%n",
        footer = {
                "  docker run -d --name phishnet-redis -p 6379:6379 redis",
                "  phishnet queue produce --file urls.txt",
                "  phishnet queue worker --threads 8",
                "  phishnet queue worker --redis-host queue.internal --retry --no-whois",
                "",
                "Set PHISHNET_REDIS_PASSWORD (and PHISHNET_REDIS_USERNAME) if your Redis needs a login."
        }
)
final class QueueCommand implements Callable<Integer> {

    static final String PASSWORD_ENV = "PHISHNET_REDIS_PASSWORD";
    static final String USERNAME_ENV = "PHISHNET_REDIS_USERNAME";

    static final String UNREACHABLE_HINT = "Is Redis running and reachable? For a local one: "
            + "docker run -d --name phishnet-redis -p 6379:6379 redis";

    /** Connects to the queue; replaced in tests. */
    @FunctionalInterface
    interface Connector {
        JobQueue connect(RedisSettings settings) throws QueueException;
    }

    @Spec
    private CommandSpec spec;

    @Override
    public Integer call() {
        throw new ParameterException(spec.commandLine(), "Missing required command: produce or worker");
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
        @Option(names = "--redis-host", paramLabel = "<host>", defaultValue = RedisSettings.DEFAULT_HOST,
                description = "Redis host (default: ${DEFAULT-VALUE})")
        String host;

        @Option(names = "--redis-port", paramLabel = "<port>", defaultValue = "" + RedisSettings.DEFAULT_PORT,
                description = "Redis port (default: ${DEFAULT-VALUE})")
        int port;

        @Option(names = "--redis-ssl", description = "Connect to Redis over TLS")
        boolean ssl;

        @Option(names = "--queue", paramLabel = "<name>", defaultValue = RedisSettings.DEFAULT_QUEUE,
                description = "Name of the Redis list used as the job queue (default: ${DEFAULT-VALUE})")
        String queue;

        RedisSettings settings(CommandSpec spec, Map<String, String> env) {
            if (port < 1 || port > 65535) {
                throw new ParameterException(spec.commandLine(),
                        "Invalid value for option '--redis-port': " + port + " is not a valid port (1-65535)");
            }
            if (queue.isBlank()) {
                throw new ParameterException(spec.commandLine(), "Invalid value for option '--queue': must not be empty");
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
            description = "Queue every URL in a file (one per line, '#' comments allowed) as a scan job.",
            synopsisHeading = "%nUsage:%n",
            descriptionHeading = "%n",
            optionListHeading = "%nOptions:%n"
    )
    static final class ProduceCommand implements Callable<Integer> {

        @Spec
        CommandSpec spec;

        @Mixin
        RedisOptions redis = new RedisOptions();

        @Option(names = "--file", paramLabel = "<urls.txt>", required = true,
                description = "File of URLs to queue, the same format as --batch")
        String file;

        @Option(names = {"--quiet", "-q"}, description = "Print only the number of jobs queued")
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
                String reason = e instanceof NoSuchFileException ? "file not found" : e.getMessage();
                environment.err().println("Error: could not read " + file + ": " + reason);
                return 1;
            }
            if (targets.isEmpty()) {
                environment.out().println(quiet ? "0" : "Nothing to queue: " + file + " contains no URLs.");
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
                environment.err().println("Error: " + e.getMessage());
                if (!e.isFatal()) {
                    environment.err().println(UNREACHABLE_HINT);
                }
                return 1;
            }
            environment.out().println(quiet ? Integer.toString(payloads.size())
                    : "Queued " + payloads.size() + " job(s) on " + settings.describe() + "; " + waiting
                    + " waiting in total. Start workers with: phishnet queue worker");
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
            description = "Take URLs off the queue and scan them, recording each result in the scan history. "
                    + "Runs until Ctrl+C (or, with --exit-when-empty, until the queue is empty).",
            synopsisHeading = "%nUsage:%n",
            descriptionHeading = "%n",
            optionListHeading = "%nOptions:%n"
    )
    static final class WorkerCommand implements Callable<Integer> {

        @Spec
        CommandSpec spec;

        @Mixin
        RedisOptions redis = new RedisOptions();

        @Option(names = "--threads", paramLabel = "<n>",
                description = "Jobs to scan in parallel, each thread with its own Redis connection "
                        + "(default: one per CPU core)")
        Integer threads;

        @Option(names = "--retry",
                description = "If Redis is unreachable or the connection drops, keep retrying with backoff "
                        + "(2s doubling up to 1 min) instead of stopping with an error")
        boolean retry;

        @Option(names = "--exit-when-empty",
                description = "Stop once the queue is empty instead of waiting for more jobs")
        boolean exitWhenEmpty;

        @Option(names = "--no-whois", description = "Skip the live WHOIS domain-age lookup")
        boolean noWhois;

        @Option(names = "--config", paramLabel = "<path>",
                description = "Use a custom YAML config instead of the bundled default")
        String configPath;

        @Option(names = "--history-file", paramLabel = "<path>",
                description = "Scan history CSV (default: ./phishnet-history.csv)")
        String historyFile;

        @Option(names = "--no-history", description = "Do not append results to the scan history CSV")
        boolean noHistory;

        @Option(names = "--history-db", paramLabel = "<path>",
                description = "Scan history database (default: ~/.phishnet/phishnet-history.db)")
        String historyDb;

        @Option(names = "--no-history-db", description = "Do not record results in the scan history database")
        boolean noHistoryDb;

        @ArgGroup(exclusive = true, multiplicity = "0..1", heading = "%n")
        Verbosity verbosity = new Verbosity();

        static final class Verbosity {
            @Option(names = {"--verbose", "-v"},
                    description = "Also show every signal, the domain age, and which thread scanned each job")
            boolean verbose;

            @Option(names = {"--quiet", "-q"}, description = "Print only one line per job (LEVEL SCORE TARGET)")
            boolean quiet;
        }

        @Option(names = "--no-color", description = "Disable ANSI colors even if the terminal supports them")
        boolean noColor;

        private final Environment environment;

        WorkerCommand(Environment environment) {
            this.environment = environment;
        }

        @Override
        public Integer call() throws InterruptedException {
            if (threads != null && (threads < 1 || threads > ParallelScanner.MAX_THREADS)) {
                throw new ParameterException(spec.commandLine(), "Invalid value for option '--threads': " + threads
                        + " (must be 1-" + ParallelScanner.MAX_THREADS + ")");
            }
            int threadCount = threads != null ? threads : ParallelScanner.defaultThreads();
            RedisSettings settings = redis.settings(spec, environment.env());
            PrintStream err = environment.err();

            PhishNetConfig config;
            try {
                config = configPath != null ? ConfigLoader.load(Path.of(configPath)) : ConfigLoader.loadDefault();
            } catch (RuntimeException e) {
                err.println("Error: could not load config: " + e.getMessage());
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
                err.println("Warning: " + e.getMessage() + ". Retrying in the background (--retry)...");
            }

            reporter.header("PhishNet queue worker: " + threadCount + " thread(s) taking jobs from "
                    + settings.describe() + ". " + (exitWhenEmpty ? "Stops when the queue is empty."
                    : "Press Ctrl+C to stop."));

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
