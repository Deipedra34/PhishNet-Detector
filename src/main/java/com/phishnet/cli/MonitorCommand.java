package com.phishnet.cli;

import com.phishnet.analyzer.EmailAnalyzer;
import com.phishnet.analyzer.UrlAnalyzer;
import com.phishnet.history.HistoryDatabase;
import com.phishnet.i18n.Messages;
import com.phishnet.mail.ImapMailSource;
import com.phishnet.mail.MailMonitorService;
import com.phishnet.mail.MailProtocol;
import com.phishnet.mail.MailServerSettings;
import com.phishnet.mail.MailServerSettings.Security;
import com.phishnet.mail.MailSource;
import com.phishnet.mail.MonitorActions;
import com.phishnet.mail.Pop3MailSource;
import com.phishnet.model.PhishNetConfig;
import com.phishnet.model.RiskLevel;
import com.phishnet.scoring.RiskScorer;
import com.phishnet.util.ColorSupport;
import com.phishnet.util.ConfigLoader;
import picocli.CommandLine.ArgGroup;
import picocli.CommandLine.Command;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Model.OptionSpec;
import picocli.CommandLine.Option;
import picocli.CommandLine.ParameterException;
import picocli.CommandLine.Spec;

import java.io.Console;
import java.io.PrintStream;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;

/**
 * {@code phishnet monitor}: watches a mailbox over IMAP (or POP3) and scans every new
 * email as it arrives, with the same analyzer and scoring as {@code phishnet --email}.
 * {@link Main#run} hands it the arguments after "monitor", like {@code serve}.
 *
 * <p>The password is never a plain command-line value: it comes from a masked prompt
 * ({@code --password}, or automatically in a terminal) or the
 * {@value #PASSWORD_ENV} environment variable, and is only ever passed to the mail server.
 */
@Command(
        name = "phishnet " + Main.MONITOR_COMMAND,
        resourceBundle = Main.MESSAGES_BUNDLE,
        mixinStandardHelpOptions = true,
        versionProvider = Main.VersionProvider.class,
        sortOptions = false,
        descriptionHeading = "%n")
final class MonitorCommand implements Callable<Integer> {

    static final String PASSWORD_ENV = "PHISHNET_MAIL_PASSWORD";
    static final String USERNAME_ENV = "PHISHNET_MAIL_USERNAME";

    /** Shortest allowed --poll-interval; anything faster is impolite to the mail server. */
    static final int MIN_POLL_SECONDS = 5;

    /** Asks the user for the password without echoing it; returns null if there's no terminal. */
    interface PasswordPrompt {
        char[] readPassword(String prompt);
    }

    /** Creates the mailbox connection; replaced in tests by a fake that needs no server. */
    interface SourceFactory {
        MailSource create(MailServerSettings settings, MonitorActions actions);
    }

    static final SourceFactory REAL_SOURCES = (settings, actions) -> settings.protocol() == MailProtocol.IMAP
            ? new ImapMailSource(settings, actions)
            : new Pop3MailSource(settings);

    static final PasswordPrompt CONSOLE_PROMPT = prompt -> {
        Console console = System.console();
        return console == null ? null : console.readPassword("%s", prompt);
    };

    @Spec
    private CommandSpec spec;

    // --- mailbox ------------------------------------------------------------------------

    @Option(names = "--host", paramLabel = "<host>", required = true)
    private String host;

    @Option(names = "--port", paramLabel = "<port>")
    private Integer port;

    @Option(names = "--username", paramLabel = "<user>")
    private String username;

    @Option(names = "--password", interactive = true, arity = "0", echo = false,
            prompt = "Mail password (input hidden): ")
    private char[] password;

    @Option(names = "--protocol", paramLabel = "<protocol>", defaultValue = "IMAP")
    private MailProtocol protocol;

    @ArgGroup(exclusive = true, multiplicity = "1", headingKey = "phishnet monitor.group.ssl")
    private SecurityOptions security;

    private static final class SecurityOptions {
        @Option(names = "--ssl")
        boolean ssl;

        @Option(names = "--starttls")
        boolean starttls;

        @Option(names = "--allow-plaintext")
        boolean plaintext;
    }

    @Option(names = "--folder", paramLabel = "<name>", defaultValue = MailServerSettings.DEFAULT_FOLDER)
    private String folder;

    @Option(names = "--oauth2")
    private boolean oauth2;

    @Option(names = "--poll-interval", paramLabel = "<seconds>", defaultValue = "60")
    private int pollSeconds;

    // --- actions ------------------------------------------------------------------------

    @Option(names = "--act-on", paramLabel = "<level>", defaultValue = "MEDIUM")
    private RiskLevel actOn;

    @Option(names = "--flag-suspicious")
    private boolean flagSuspicious;

    @Option(names = "--move-to-folder", paramLabel = "<name>")
    private String moveToFolder;

    @Option(names = "--record-all")
    private boolean recordAll;

    // --- history / output / config -----------------------------------------------------------

    @Option(names = "--history-file", paramLabel = "<path>")
    private String historyFile;

    @Option(names = "--no-history")
    private boolean noHistory;

    @Option(names = "--history-db", paramLabel = "<path>")
    private String historyDb;

    @Option(names = "--no-history-db")
    private boolean noHistoryDb;

    @Option(names = "--config", paramLabel = "<path>")
    private String configPath;

    @ArgGroup(exclusive = true, multiplicity = "0..1", heading = "%n")
    private Verbosity verbosity = new Verbosity();

    private static final class Verbosity {
        @Option(names = {"--verbose", "-v"})
        boolean verbose;

        @Option(names = {"--quiet", "-q"})
        boolean quiet;
    }

    @Option(names = "--no-color")
    private boolean noColor;

    private final PrintStream out;
    private final PrintStream err;
    private final Map<String, String> environment;
    private final PasswordPrompt prompt;
    private final SourceFactory sources;
    private final Clock clock;
    private final boolean installShutdownHook;

    MonitorCommand(PrintStream out, PrintStream err) {
        this(out, err, System.getenv(), CONSOLE_PROMPT, REAL_SOURCES, Clock.systemDefaultZone(), true);
    }

    /** Everything that touches the outside world, swappable for tests. */
    MonitorCommand(PrintStream out, PrintStream err, Map<String, String> environment, PasswordPrompt prompt,
                   SourceFactory sources, Clock clock, boolean installShutdownHook) {
        this.out = out;
        this.err = err;
        this.environment = environment;
        this.prompt = prompt;
        this.sources = sources;
        this.clock = clock;
        this.installShutdownHook = installShutdownHook;
    }

    @Override
    public Integer call() {
        Security encryption = security.ssl ? Security.SSL : security.starttls ? Security.STARTTLS : Security.NONE;
        validate();
        String user = username != null ? username : environment.get(USERNAME_ENV);
        if (user == null || user.isBlank()) {
            throw usageError(Messages.text("monitor.error.username", USERNAME_ENV));
        }
        int serverPort = port != null ? port : MailServerSettings.defaultPort(protocol, encryption);

        PhishNetConfig config;
        try {
            config = configPath != null ? ConfigLoader.load(Path.of(configPath)) : ConfigLoader.loadDefault();
        } catch (RuntimeException e) {
            err.println(Messages.text("cli.error.config", e.getMessage()));
            return 1;
        }

        String secret = resolvePassword(user, serverPort);
        MailServerSettings settings = new MailServerSettings(protocol, host, serverPort, user, secret,
                encryption, folder, oauth2);
        MonitorActions actions = new MonitorActions(actOn, flagSuspicious, moveToFolder, recordAll);

        Path csvFile = historyFile != null ? Path.of(historyFile) : Path.of("phishnet-history.csv");
        HistoryWriter csv = new HistoryWriter(csvFile, !noHistory, err);
        HistoryDatabase database = new HistoryDatabase(
                historyDb != null ? Path.of(historyDb) : HistoryDatabase.defaultPath(), !noHistoryDb, err);
        MailMonitorService.Recorder recorder = (mail, analysis, score) -> {
            csv.record(mail.label(), HistoryWriter.TargetType.EMAIL, score);
            database.recordEmail(mail.label(), analysis.senderAddress(), analysis.subject(), score);
        };

        OutputLevel level = verbosity.quiet ? OutputLevel.QUIET
                : verbosity.verbose ? OutputLevel.VERBOSE : OutputLevel.NORMAL;
        String waitDescription = protocol == MailProtocol.POP3
                ? Messages.text("monitor.polling.pop3", pollSeconds)
                : Messages.text("monitor.polling.noIdle", pollSeconds);
        MonitorReporter reporter = new MonitorReporter(out, err, level, ColorSupport.isEnabled(noColor), clock,
                waitDescription);

        if (encryption == Security.NONE) {
            err.println(Messages.text("monitor.plaintextWarning"));
        }
        reporter.header(header(settings, actions, csvFile, database));

        UrlAnalyzer urlAnalyzer = new UrlAnalyzer(config);
        MailMonitorService service = new MailMonitorService(sources.create(settings, actions),
                new EmailAnalyzer(config, urlAnalyzer), new RiskScorer(config), actions, recorder, reporter,
                Duration.ofSeconds(pollSeconds));

        Thread hook = new Thread(() -> {
            service.stop();
            try {
                service.awaitFinished(Duration.ofSeconds(10));
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }, "phishnet-monitor-shutdown");
        if (installShutdownHook) {
            Runtime.getRuntime().addShutdownHook(hook);
        }
        MailMonitorService.Exit exit = service.run();
        // An interrupt is only ever the monitor's stop signal; don't leak it to whatever
        // runs on this thread next (it would make interruptible file I/O fail).
        Thread.interrupted();
        if (installShutdownHook) {
            try {
                Runtime.getRuntime().removeShutdownHook(hook);
            } catch (IllegalStateException alreadyShuttingDown) {
                // the hook is what stopped the monitor
            }
        }
        return exit == MailMonitorService.Exit.FATAL_ERROR ? 1 : 0;
    }

    /** Option combinations picocli can't check on its own. */
    private void validate() {
        if (port != null && (port < 1 || port > 65535)) {
            throw usageError(Messages.text("cli.invalid.port", "--port", port, "1-65535"));
        }
        if (pollSeconds < MIN_POLL_SECONDS) {
            throw usageError(Messages.text("monitor.error.pollInterval", MIN_POLL_SECONDS));
        }
        if (actOn == RiskLevel.LOW) {
            throw usageError(Messages.text("monitor.error.actOn"));
        }
        if (moveToFolder != null && moveToFolder.isBlank()) {
            throw usageError(Messages.text("monitor.error.moveToFolderEmpty"));
        }
        if (protocol == MailProtocol.POP3) {
            if (flagSuspicious || moveToFolder != null) {
                throw usageError(Messages.text("monitor.error.pop3Actions"));
            }
            if (!MailServerSettings.DEFAULT_FOLDER.equalsIgnoreCase(folder)) {
                throw usageError(Messages.text("monitor.error.pop3Folder"));
            }
        }
        if (moveToFolder != null && moveToFolder.equalsIgnoreCase(folder)) {
            throw usageError(Messages.text("monitor.error.sameFolder", folder));
        }
    }

    /** --password prompt, then the environment variable, then a prompt when there's a terminal. */
    private String resolvePassword(String user, int serverPort) {
        char[] chars = password;
        if (chars == null || chars.length == 0) {
            String fromEnv = environment.get(PASSWORD_ENV);
            if (fromEnv != null && !fromEnv.isEmpty()) {
                return fromEnv;
            }
            chars = prompt.readPassword(Messages.text(oauth2 ? "monitor.prompt.token" : "monitor.prompt.password",
                    user, host + ":" + serverPort) + " ");
        }
        if (chars == null || chars.length == 0) {
            throw usageError(Messages.text("monitor.error.noPassword", PASSWORD_ENV));
        }
        String secret = new String(chars);
        Arrays.fill(chars, '\0');
        return secret;
    }

    private List<String> header(MailServerSettings settings, MonitorActions actions, Path csvFile,
                                HistoryDatabase database) {
        List<String> lines = new ArrayList<>();
        lines.add(Messages.text("monitor.header.watching", settings.folder(), settings.describe(),
                settings.username()));
        String scope = Messages.text(actions.minLevel() == RiskLevel.HIGH ? "monitor.scope.high"
                : "monitor.scope.mediumHigh");
        if (actions.mutatesMailbox()) {
            String change;
            if (actions.flagSuspicious() && actions.moveToFolder() != null) {
                change = Messages.text("monitor.change.flagAndMove", actions.moveToFolder());
            } else if (actions.flagSuspicious()) {
                change = Messages.text("monitor.change.flag");
            } else {
                change = Messages.text("monitor.change.move", actions.moveToFolder());
            }
            lines.add(Messages.text("monitor.header.actions", scope, change));
        } else {
            lines.add(Messages.text("monitor.header.readOnly", scope));
        }
        List<String> targets = new ArrayList<>();
        if (!noHistory) {
            targets.add(csvFile.toString());
        }
        if (database.writesEnabled()) {
            targets.add(database.file().toString());
        }
        if (!targets.isEmpty()) {
            String where = targets.size() == 1 ? targets.get(0)
                    : Messages.text("monitor.both", targets.get(0), targets.get(1));
            lines.add(Messages.text(actions.recordAll() ? "monitor.header.recordAll" : "monitor.header.recordSuspicious",
                    where));
        }
        lines.add(Messages.text("monitor.header.fromNow") + " " + Messages.text("cli.pressCtrlC"));
        return lines;
    }

    /**
     * Catches a password typed straight onto the command line ({@code --password=secret} or
     * {@code --password secret}) before picocli parses it: picocli's own error message
     * would repeat the value back to the terminal.
     *
     * @return a usage error message that doesn't contain the value, or null if the arguments are fine
     */
    static String passwordValueError(String[] args) {
        for (int i = 0; i < args.length; i++) {
            boolean inline = args[i].startsWith("--password=");
            boolean separate = args[i].equals("--password") && i + 1 < args.length && !args[i + 1].startsWith("-");
            if (inline || separate) {
                return Messages.text("monitor.error.passwordValue", PASSWORD_ENV);
            }
        }
        return null;
    }

    /**
     * Picocli takes an interactive option's prompt only from its annotation, so --password
     * is rebuilt with the prompt in the run's language. The options declared after it are
     * re-added behind it, keeping the help in declaration order.
     */
    static void localizePasswordPrompt(CommandSpec spec) {
        String prompt = Messages.text("monitor.passwordPrompt") + " ";
        OptionSpec password = spec.findOption("--password");
        if (password == null || password.prompt().equals(prompt)) {
            return;
        }
        List<OptionSpec> ungrouped = spec.options().stream().filter(option -> option.group() == null).toList();
        List<OptionSpec> tail = ungrouped.subList(ungrouped.indexOf(password), ungrouped.size());
        tail.forEach(spec::remove);
        for (OptionSpec option : tail) {
            spec.addOption(option == password ? option.toBuilder().prompt(prompt).build() : option);
        }
    }

    private ParameterException usageError(String message) {
        return new ParameterException(spec.commandLine(), message);
    }
}
