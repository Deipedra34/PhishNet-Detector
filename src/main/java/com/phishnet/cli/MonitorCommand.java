package com.phishnet.cli;

import com.phishnet.analyzer.EmailAnalyzer;
import com.phishnet.analyzer.UrlAnalyzer;
import com.phishnet.history.HistoryDatabase;
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
        mixinStandardHelpOptions = true,
        versionProvider = Main.VersionProvider.class,
        sortOptions = false,
        description = "Watch a mailbox over IMAP (or POP3) and scan each new email for phishing as it arrives. "
                + "Read-only unless --flag-suspicious or --move-to-folder is given. Runs until Ctrl+C.",
        synopsisHeading = "%nUsage:%n",
        descriptionHeading = "%n",
        optionListHeading = "%nOptions:%n",
        footerHeading = "%nExamples:%n",
        footer = {
                "  phishnet monitor --host imap.gmail.com --username you@gmail.com --ssl",
                "  phishnet monitor --host mail.example.com --username alice --starttls \\",
                "      --password",
                "  PHISHNET_MAIL_PASSWORD=... phishnet monitor --host mail.example.com \\",
                "      --username alice --ssl --flag-suspicious --move-to-folder Suspicious",
                "",
                "Gmail, Outlook.com, iCloud and Yahoo need an app password (or --oauth2),",
                "not your regular account password. See the README's \"Real-Time Email",
                "Monitoring\" section for provider settings and security notes."
        }
)
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

    @Option(names = "--host", paramLabel = "<host>", required = true,
            description = "Mail server, e.g. imap.gmail.com")
    private String host;

    @Option(names = "--port", paramLabel = "<port>",
            description = "Server port (default: 993 for IMAP with --ssl, 143 without; 995/110 for POP3)")
    private Integer port;

    @Option(names = "--username", paramLabel = "<user>",
            description = "Login name, usually your email address (or set " + USERNAME_ENV + ")")
    private String username;

    @Option(names = "--password", interactive = true, arity = "0", echo = false,
            prompt = "Mail password (input hidden): ",
            description = "Prompt for the password without echoing it. Without this option the password is "
                    + "read from " + PASSWORD_ENV + ", or prompted for when running in a terminal. "
                    + "It is never accepted as a plain command-line value.")
    private char[] password;

    @Option(names = "--protocol", paramLabel = "<protocol>", defaultValue = "IMAP",
            description = "${COMPLETION-CANDIDATES} (default: ${DEFAULT-VALUE}). POP3 is polling-only and read-only.")
    private MailProtocol protocol;

    @ArgGroup(exclusive = true, multiplicity = "1", heading = "%nEncryption (one is required):%n")
    private SecurityOptions security;

    private static final class SecurityOptions {
        @Option(names = "--ssl", description = "Use TLS from the start (IMAPS / POP3S) - the usual choice")
        boolean ssl;

        @Option(names = "--starttls", description = "Connect in plain text, then require an upgrade with STARTTLS")
        boolean starttls;

        @Option(names = "--allow-plaintext",
                description = "No encryption at all: the password is sent readable. Only for a local test server.")
        boolean plaintext;
    }

    @Option(names = "--folder", paramLabel = "<name>", defaultValue = MailServerSettings.DEFAULT_FOLDER,
            description = "IMAP folder to watch (default: ${DEFAULT-VALUE})")
    private String folder;

    @Option(names = "--oauth2",
            description = "Log in with OAuth2 (SASL XOAUTH2): the password value is an access token you obtained "
                    + "from your provider")
    private boolean oauth2;

    @Option(names = "--poll-interval", paramLabel = "<seconds>", defaultValue = "60",
            description = "How often to check for new mail when the server doesn't support IMAP IDLE, "
                    + "and always for POP3 (default: ${DEFAULT-VALUE}, minimum " + MIN_POLL_SECONDS + ")")
    private int pollSeconds;

    // --- actions ------------------------------------------------------------------------

    @Option(names = "--act-on", paramLabel = "<level>", defaultValue = "MEDIUM",
            description = "Lowest risk level treated as suspicious: MEDIUM or HIGH (default: ${DEFAULT-VALUE})")
    private RiskLevel actOn;

    @Option(names = "--flag-suspicious",
            description = "Opt in: mark suspicious messages with \\Flagged (and the $Phishing keyword where "
                    + "allowed). Changes the mailbox; IMAP only.")
    private boolean flagSuspicious;

    @Option(names = "--move-to-folder", paramLabel = "<name>",
            description = "Opt in: move suspicious messages to this folder, creating it if needed. "
                    + "Changes the mailbox; IMAP only.")
    private String moveToFolder;

    @Option(names = "--record-all",
            description = "Record every scanned message in the scan history, not only suspicious ones")
    private boolean recordAll;

    // --- history / output / config -----------------------------------------------------------

    @Option(names = "--history-file", paramLabel = "<path>",
            description = "Scan history CSV (default: ./phishnet-history.csv)")
    private String historyFile;

    @Option(names = "--no-history", description = "Do not append results to the scan history CSV")
    private boolean noHistory;

    @Option(names = "--history-db", paramLabel = "<path>",
            description = "Scan history database (default: ~/.phishnet/phishnet-history.db)")
    private String historyDb;

    @Option(names = "--no-history-db", description = "Do not record results in the scan history database")
    private boolean noHistoryDb;

    @Option(names = "--config", paramLabel = "<path>",
            description = "Use a custom YAML config instead of the bundled default")
    private String configPath;

    @ArgGroup(exclusive = true, multiplicity = "0..1", heading = "%n")
    private Verbosity verbosity = new Verbosity();

    private static final class Verbosity {
        @Option(names = {"--verbose", "-v"},
                description = "Also show every message's signals and mailbox label, and connection attempts")
        boolean verbose;

        @Option(names = {"--quiet", "-q"},
                description = "Print only one line per scanned message (LEVEL SCORE LABEL)")
        boolean quiet;
    }

    @Option(names = "--no-color", description = "Disable ANSI colors even if the terminal supports them")
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
            throw usageError("Missing username: pass --username or set " + USERNAME_ENV);
        }
        int serverPort = port != null ? port : MailServerSettings.defaultPort(protocol, encryption);

        PhishNetConfig config;
        try {
            config = configPath != null ? ConfigLoader.load(Path.of(configPath)) : ConfigLoader.loadDefault();
        } catch (RuntimeException e) {
            err.println("Error: could not load config: " + e.getMessage());
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
                ? "polling every " + pollSeconds + "s - POP3 can't push new mail"
                : "polling every " + pollSeconds + "s - the server doesn't support IDLE";
        MonitorReporter reporter = new MonitorReporter(out, err, level, ColorSupport.isEnabled(noColor), clock,
                waitDescription);

        if (encryption == Security.NONE) {
            err.println("Warning: --allow-plaintext sends your password and mail over the network unencrypted.");
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
            throw usageError("Invalid value for option '--port': " + port + " is not a valid port (1-65535)");
        }
        if (pollSeconds < MIN_POLL_SECONDS) {
            throw usageError("Invalid value for option '--poll-interval': must be at least "
                    + MIN_POLL_SECONDS + " seconds");
        }
        if (actOn == RiskLevel.LOW) {
            throw usageError("Invalid value for option '--act-on': use MEDIUM or HIGH "
                    + "(LOW would treat every message as suspicious)");
        }
        if (moveToFolder != null && moveToFolder.isBlank()) {
            throw usageError("Invalid value for option '--move-to-folder': the folder name must not be empty");
        }
        if (protocol == MailProtocol.POP3) {
            if (flagSuspicious || moveToFolder != null) {
                throw usageError("--flag-suspicious and --move-to-folder need IMAP: POP3 has no flags or folders");
            }
            if (!MailServerSettings.DEFAULT_FOLDER.equalsIgnoreCase(folder)) {
                throw usageError("--folder needs IMAP: POP3 only has INBOX");
            }
        }
        if (moveToFolder != null && moveToFolder.equalsIgnoreCase(folder)) {
            throw usageError("--move-to-folder must be a different folder than the one being watched (" + folder + ")");
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
            chars = prompt.readPassword((oauth2 ? "OAuth2 access token" : "Password") + " for " + user + " on "
                    + host + ":" + serverPort + " (input hidden): ");
        }
        if (chars == null || chars.length == 0) {
            throw usageError("No password: set " + PASSWORD_ENV + ", or run in a terminal (or with --password) "
                    + "to be prompted for it");
        }
        String secret = new String(chars);
        Arrays.fill(chars, '\0');
        return secret;
    }

    private List<String> header(MailServerSettings settings, MonitorActions actions, Path csvFile,
                                HistoryDatabase database) {
        List<String> lines = new ArrayList<>();
        lines.add("PhishNet is monitoring " + settings.folder() + " on " + settings.describe()
                + " as " + settings.username());
        String scope = actions.minLevel() == RiskLevel.HIGH ? "HIGH" : "MEDIUM and HIGH";
        if (actions.mutatesMailbox()) {
            List<String> changes = new ArrayList<>();
            if (actions.flagSuspicious()) {
                changes.add("flagged");
            }
            if (actions.moveToFolder() != null) {
                changes.add("moved to \"" + actions.moveToFolder() + "\"");
            }
            lines.add("Suspicious mail (" + scope + " risk) is " + String.join(" and ", changes) + ".");
        } else {
            lines.add("Read-only: the mailbox is never changed. Suspicious mail (" + scope + " risk) is reported.");
        }
        List<String> targets = new ArrayList<>();
        if (!noHistory) {
            targets.add(csvFile.toString());
        }
        if (database.writesEnabled()) {
            targets.add(database.file().toString());
        }
        if (!targets.isEmpty()) {
            lines.add("Recording " + (actions.recordAll() ? "every scanned message" : "suspicious mail")
                    + " to " + String.join(" and ", targets) + ".");
        }
        lines.add("Only mail arriving from now on is scanned. Press Ctrl+C to stop.");
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
                return "--password doesn't take a value on the command line (it would end up in your shell "
                        + "history). Use --password alone to be prompted, or set " + PASSWORD_ENV + ".";
            }
        }
        return null;
    }

    private ParameterException usageError(String message) {
        return new ParameterException(spec.commandLine(), message);
    }
}
