package com.phishnet.cli;

import com.phishnet.analyzer.EmailAnalyzer;
import com.phishnet.analyzer.UrlAnalyzer;
import com.phishnet.model.EmailAnalysisResult;
import com.phishnet.model.PhishNetConfig;
import com.phishnet.model.RiskLevel;
import com.phishnet.model.RiskScore;
import com.phishnet.model.UrlAnalysisResult;
import com.phishnet.scoring.RiskScorer;
import com.phishnet.util.ColorSupport;
import com.phishnet.util.ConfigLoader;
import picocli.CommandLine;
import picocli.CommandLine.ArgGroup;
import picocli.CommandLine.Command;
import picocli.CommandLine.IVersionProvider;
import picocli.CommandLine.Option;
import picocli.CommandLine.ParameterException;

import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;
import java.util.concurrent.Callable;

/**
 * Command-line entry point for PhishNet Detector, built on
 * <a href="https://picocli.info">picocli</a>. Run {@code phishnet --help} for
 * full usage, or see the README's Usage section.
 */
@Command(
        name = "phishnet",
        mixinStandardHelpOptions = true,
        versionProvider = Main.VersionProvider.class,
        sortOptions = false,
        description = "Analyzes URLs, TLS certificates, and .eml email files for phishing indicators, "
                + "and combines whatever it finds into a single 0-100 risk score with a Low/Medium/High "
                + "label and a plain-language recommendation.",
        synopsisHeading = "%nUsage:%n",
        descriptionHeading = "%n",
        optionListHeading = "%nOptions:%n",
        footerHeading = "%nExamples:%n",
        footer = {
                "  phishnet --url https://example.com",
                "  phishnet --email suspicious.eml --verbose",
                "  phishnet --batch urls.txt --json",
                "",
                "See the project README for the full option reference and sample output."
        }
)
public final class Main implements Callable<Integer> {

    // --- input options ------------------------------------------------------

    // A required ArgGroup must sit at the top level (not nested inside an optional
    // parent group) for picocli to actually enforce its multiplicity - nested inside
    // an optional group, "exactly one of url/email/batch" would only be checked once
    // *some* option in the parent was already given, letting a bare "--config foo"
    // slip through with none of url/email/batch set. --config is therefore a plain,
    // ungrouped option instead of sharing this group.
    // Not final - picocli sets this field reflectively when binding parsed values,
    // and a final field there triggers a JVM "restricted method" warning on every run.
    @ArgGroup(exclusive = true, multiplicity = "1", heading = "%nInput options:%n")
    private ModeOptions mode = new ModeOptions();

    private static final class ModeOptions {
        @Option(names = "--url", paramLabel = "<url>",
                description = "Analyze a single URL")
        private String url;

        @Option(names = "--email", paramLabel = "<file.eml>",
                description = "Analyze a single .eml email file")
        private String emailPath;

        @Option(names = "--batch", paramLabel = "<file>",
                description = "Analyze a newline-separated file of URLs ('#' comments allowed)")
        private String batchPath;
    }

    @Option(names = "--config", paramLabel = "<path>",
            description = "Use a custom YAML config instead of the bundled default")
    private String configPath;

    // --- output options ------------------------------------------------------

    @ArgGroup(exclusive = false, multiplicity = "0..1", heading = "%nOutput options:%n")
    private OutputOptions output = new OutputOptions();

    private static final class OutputOptions {
        @Option(names = "--json",
                description = "Output machine-readable JSON instead of a human-readable report")
        private boolean json;

        @Option(names = "--no-color",
                description = "Disable ANSI colors even if the terminal supports them")
        private boolean noColor;
    }

    // Kept as its own top-level group (rather than nested inside OutputOptions) so a
    // --verbose/--quiet conflict gets picocli's plain "these are mutually exclusive"
    // message instead of a confusing one that quotes the enclosing group's full synopsis.
    @ArgGroup(exclusive = true, multiplicity = "0..1", heading = "%n")
    private VerbosityOptions verbosity = new VerbosityOptions();

    private static final class VerbosityOptions {
        @Option(names = {"--verbose", "-v"},
                description = "Show each analyzer's internal reasoning, not just the summary")
        private boolean verbose;

        @Option(names = {"--quiet", "-q"},
                description = "Print one machine-parsable line only (LEVEL SCORE TARGET); "
                        + "exit code reflects risk")
        private boolean quiet;
    }

    // -h/--help and -V/--version are handled automatically via mixinStandardHelpOptions.

    private PrintStream out;
    private PrintStream err;

    private Main() {
    }

    public static void main(String[] args) {
        // System.out doesn't default to UTF-8 on every platform (notably Windows consoles),
        // and this CLI prints Unicode symbols (✓ ⚠ ✗) - force it explicitly so they render
        // correctly instead of turning into mojibake.
        PrintStream out = new PrintStream(System.out, true, StandardCharsets.UTF_8);
        PrintStream err = new PrintStream(System.err, true, StandardCharsets.UTF_8);
        int exitCode = run(args, out, err);
        if (exitCode != 0) {
            System.exit(exitCode);
        }
    }

    /** Runs against injected streams and returns an exit code - never calls System.exit itself, so it's testable. */
    static int run(String[] args, PrintStream out, PrintStream err) {
        Main app = new Main();
        app.out = out;
        app.err = err;

        CommandLine cmd = new CommandLine(app);
        cmd.setOut(new PrintWriter(out, true, StandardCharsets.UTF_8));
        cmd.setErr(new PrintWriter(err, true, StandardCharsets.UTF_8));

        // Same --no-color / NO_COLOR / non-TTY rules as the risk-level colors (AnsiColor/ColorSupport),
        // applied here too so picocli's own help/version ANSI styling doesn't disagree with them.
        // --no-color itself is scanned for directly since parsing hasn't happened yet at this point.
        boolean colorEnabled = ColorSupport.isEnabled(Arrays.asList(args).contains("--no-color"));
        cmd.setColorScheme(CommandLine.Help.defaultColorScheme(
                colorEnabled ? CommandLine.Help.Ansi.ON : CommandLine.Help.Ansi.OFF));

        cmd.setParameterExceptionHandler((ParameterException ex, String[] cmdArgs) -> {
            PrintWriter errWriter = ex.getCommandLine().getErr();
            // Some picocli exceptions (e.g. a required ArgGroup violation) already bake an
            // "Error: " prefix into getMessage(); avoid doubling it up for those.
            String message = ex.getMessage();
            errWriter.println(message.startsWith("Error: ") ? message : "Error: " + message);
            errWriter.println();
            ex.getCommandLine().usage(errWriter, ex.getCommandLine().getColorScheme());
            return ex.getCommandLine().getCommandSpec().exitCodeOnInvalidInput();
        });

        return cmd.execute(args);
    }

    @Override
    public Integer call() {
        PhishNetConfig config;
        try {
            config = configPath != null
                    ? ConfigLoader.load(Path.of(configPath))
                    : ConfigLoader.loadDefault();
        } catch (RuntimeException e) {
            err.println("Error: could not load config: " + e.getMessage());
            return 1;
        }

        UrlAnalyzer urlAnalyzer = new UrlAnalyzer(config);
        EmailAnalyzer emailAnalyzer = new EmailAnalyzer(config, urlAnalyzer);
        RiskScorer scorer = new RiskScorer(config);
        ReportFormatter formatter = new ReportFormatter();

        OutputLevel level = outputLevel();
        boolean colorEnabled = ColorSupport.isEnabled(output.noColor);
        Reporter reporter = new Reporter(out, level, colorEnabled);

        try {
            if (mode.url != null) {
                return runUrl(mode.url, urlAnalyzer, scorer, formatter, reporter, output.json, out);
            } else if (mode.emailPath != null) {
                return runEmail(mode.emailPath, emailAnalyzer, scorer, formatter, reporter, output.json, out);
            } else {
                return runBatch(mode.batchPath, urlAnalyzer, scorer, formatter, reporter, output.json, out);
            }
        } catch (IOException e) {
            err.println("Error: " + e.getMessage());
            return 1;
        }
    }

    /** QUIET if --quiet, VERBOSE if --verbose, NORMAL otherwise. */
    private OutputLevel outputLevel() {
        if (verbosity.quiet) {
            return OutputLevel.QUIET;
        }
        return verbosity.verbose ? OutputLevel.VERBOSE : OutputLevel.NORMAL;
    }

    private static int runUrl(String url, UrlAnalyzer urlAnalyzer, RiskScorer scorer, ReportFormatter formatter,
                               Reporter reporter, boolean json, PrintStream out) {
        UrlAnalysisResult result = urlAnalyzer.analyze(url);
        RiskScore score = scorer.score(result.signals());
        if (json) {
            out.println(formatter.json(url, score));
            return 0;
        }
        reporter.reportUrl(url, result, score);
        return exitCodeFor(reporter.level(), score.level());
    }

    private static int runEmail(String emailPath, EmailAnalyzer emailAnalyzer, RiskScorer scorer,
                                 ReportFormatter formatter, Reporter reporter, boolean json,
                                 PrintStream out) throws IOException {
        try (InputStream in = Files.newInputStream(Path.of(emailPath))) {
            EmailAnalysisResult result = emailAnalyzer.analyze(in);
            RiskScore score = scorer.score(result.allSignals());
            if (json) {
                String label = emailPath + " (from: " + result.senderAddress()
                        + ", subject: \"" + result.subject() + "\")";
                out.println(formatter.json(label, score));
                return 0;
            }
            reporter.reportEmail(emailPath, result, score);
            return exitCodeFor(reporter.level(), score.level());
        }
    }

    private static int runBatch(String batchPath, UrlAnalyzer urlAnalyzer, RiskScorer scorer,
                                 ReportFormatter formatter, Reporter reporter, boolean json,
                                 PrintStream out) throws IOException {
        List<String> lines = Files.readAllLines(Path.of(batchPath));
        List<AnalysisEntry> entries = new ArrayList<>();
        for (String line : lines) {
            String url = line.trim();
            if (url.isEmpty() || url.startsWith("#")) {
                continue;
            }
            UrlAnalysisResult result = urlAnalyzer.analyze(url);
            entries.add(new AnalysisEntry(url, scorer.score(result.signals())));
        }

        if (json) {
            out.println(formatter.jsonBatch(entries));
            return 0;
        }

        for (AnalysisEntry entry : entries) {
            reporter.reportBatchEntry(entry);
        }
        long high = entries.stream().filter(e -> e.score().level() == RiskLevel.HIGH).count();
        long medium = entries.stream().filter(e -> e.score().level() == RiskLevel.MEDIUM).count();
        reporter.reportBatchSummary(entries.size(), high, medium);

        return (reporter.level() == OutputLevel.QUIET && high > 0) ? 1 : 0;
    }

    /** Non-quiet modes always exit 0; quiet mode exits 1 for HIGH risk so it's usable in scripts. */
    private static int exitCodeFor(OutputLevel level, RiskLevel riskLevel) {
        return (level == OutputLevel.QUIET && riskLevel == RiskLevel.HIGH) ? 1 : 0;
    }

    /** Reads the version filtered into version.properties at build time, so it always matches the pom.xml version. */
    static final class VersionProvider implements IVersionProvider {
        @Override
        public String[] getVersion() throws Exception {
            Properties props = new Properties();
            try (InputStream in = Main.class.getResourceAsStream("/version.properties")) {
                if (in != null) {
                    props.load(in);
                }
            }
            return new String[] {"phishnet " + props.getProperty("version", "unknown")};
        }
    }
}
