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

import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Command-line entry point for PhishNet Detector.
 *
 * <pre>
 *   java -jar phishnet.jar --url &lt;url&gt; [--verbose|--quiet] [--json] [--no-color] [--config &lt;path&gt;]
 *   java -jar phishnet.jar --email &lt;file.eml&gt; [--verbose|--quiet] [--json] [--no-color] [--config &lt;path&gt;]
 *   java -jar phishnet.jar --batch &lt;file-of-urls&gt; [--verbose|--quiet] [--json] [--no-color] [--config &lt;path&gt;]
 * </pre>
 */
public final class Main {

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
        CliArgs parsed;
        try {
            parsed = CliArgs.parse(args);
        } catch (IllegalArgumentException e) {
            err.println("Error: " + e.getMessage());
            err.println();
            err.println(usage());
            return 2;
        }

        if (parsed.help()) {
            out.println(usage());
            return 0;
        }

        PhishNetConfig config;
        try {
            config = parsed.configPath() != null
                    ? ConfigLoader.load(Path.of(parsed.configPath()))
                    : ConfigLoader.loadDefault();
        } catch (RuntimeException e) {
            err.println("Error: could not load config: " + e.getMessage());
            return 1;
        }

        UrlAnalyzer urlAnalyzer = new UrlAnalyzer(config);
        EmailAnalyzer emailAnalyzer = new EmailAnalyzer(config, urlAnalyzer);
        RiskScorer scorer = new RiskScorer(config);
        ReportFormatter formatter = new ReportFormatter();

        OutputLevel level = parsed.outputLevel();
        boolean colorEnabled = ColorSupport.isEnabled(parsed.noColor());
        Reporter reporter = new Reporter(out, level, colorEnabled);

        try {
            if (parsed.url() != null) {
                return runUrl(parsed.url(), urlAnalyzer, scorer, formatter, reporter, parsed.json(), out);
            } else if (parsed.emailPath() != null) {
                return runEmail(parsed.emailPath(), emailAnalyzer, scorer, formatter, reporter, parsed.json(), out);
            } else {
                return runBatch(parsed.batchPath(), urlAnalyzer, scorer, formatter, reporter, parsed.json(), out);
            }
        } catch (IOException e) {
            err.println("Error: " + e.getMessage());
            return 1;
        }
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

    private static String usage() {
        return "PhishNet Detector - phishing detection tool\n\n"
                + "Usage:\n"
                + "  java -jar phishnet.jar --url <url> [options]\n"
                + "  java -jar phishnet.jar --email <file.eml> [options]\n"
                + "  java -jar phishnet.jar --batch <file-of-urls> [options]\n\n"
                + "Options:\n"
                + "  --url <url>            Analyze a single URL\n"
                + "  --email <file.eml>     Analyze a single .eml email file\n"
                + "  --batch <file>         Analyze a newline-separated file of URLs ('#' comments allowed)\n"
                + "  --verbose, -v          Show each analyzer's internal reasoning, not just the summary\n"
                + "  --quiet, -q            Print one machine-parsable line only (LEVEL SCORE TARGET); "
                + "exit code reflects risk\n"
                + "  --json                 Output machine-readable JSON instead of a human-readable report\n"
                + "  --no-color             Disable ANSI colors even if the terminal supports them\n"
                + "  --config <path>        Use a custom YAML config instead of the bundled default\n"
                + "  --help, -h             Show this help message";
    }
}
