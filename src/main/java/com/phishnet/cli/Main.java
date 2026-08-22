package com.phishnet.cli;

import com.phishnet.analyzer.EmailAnalyzer;
import com.phishnet.analyzer.UrlAnalyzer;
import com.phishnet.model.EmailAnalysisResult;
import com.phishnet.model.PhishNetConfig;
import com.phishnet.model.RiskLevel;
import com.phishnet.model.RiskScore;
import com.phishnet.model.UrlAnalysisResult;
import com.phishnet.scoring.RiskScorer;
import com.phishnet.util.ConfigLoader;

import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Command-line entry point for PhishNet Detector.
 *
 * <pre>
 *   java -jar phishnet.jar --url &lt;url&gt; [--json] [--config &lt;path&gt;]
 *   java -jar phishnet.jar --email &lt;file.eml&gt; [--json] [--config &lt;path&gt;]
 *   java -jar phishnet.jar --batch &lt;file-of-urls&gt; [--json] [--config &lt;path&gt;]
 * </pre>
 */
public final class Main {

    private Main() {
    }

    public static void main(String[] args) {
        int exitCode = run(args, System.out, System.err);
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

        try {
            if (parsed.url() != null) {
                runUrl(parsed.url(), urlAnalyzer, scorer, formatter, parsed.json(), out);
                return 0;
            } else if (parsed.emailPath() != null) {
                runEmail(parsed.emailPath(), emailAnalyzer, scorer, formatter, parsed.json(), out);
                return 0;
            } else {
                runBatch(parsed.batchPath(), urlAnalyzer, scorer, formatter, parsed.json(), out);
                return 0;
            }
        } catch (IOException e) {
            err.println("Error: " + e.getMessage());
            return 1;
        }
    }

    private static void runUrl(String url, UrlAnalyzer urlAnalyzer, RiskScorer scorer,
                                ReportFormatter formatter, boolean json, PrintStream out) {
        UrlAnalysisResult result = urlAnalyzer.analyze(url);
        RiskScore score = scorer.score(result.signals());
        out.println(json ? formatter.json(url, score) : formatter.humanReadable(url, score));
    }

    private static void runEmail(String emailPath, EmailAnalyzer emailAnalyzer, RiskScorer scorer,
                                 ReportFormatter formatter, boolean json, PrintStream out) throws IOException {
        try (InputStream in = Files.newInputStream(Path.of(emailPath))) {
            EmailAnalysisResult result = emailAnalyzer.analyze(in);
            RiskScore score = scorer.score(result.allSignals());
            String label = emailPath + " (from: " + result.senderAddress()
                    + ", subject: \"" + result.subject() + "\")";
            out.println(json ? formatter.json(label, score) : formatter.humanReadable(label, score));
        }
    }

    private static void runBatch(String batchPath, UrlAnalyzer urlAnalyzer, RiskScorer scorer,
                                  ReportFormatter formatter, boolean json, PrintStream out) throws IOException {
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
            return;
        }

        for (AnalysisEntry entry : entries) {
            out.println(formatter.humanReadable(entry.label(), entry.score()));
            out.println("---");
        }
        long high = entries.stream().filter(e -> e.score().level() == RiskLevel.HIGH).count();
        long medium = entries.stream().filter(e -> e.score().level() == RiskLevel.MEDIUM).count();
        out.println("Summary: " + entries.size() + " URL(s) analyzed - " + high + " high risk, "
                + medium + " medium risk");
    }

    private static String usage() {
        return "PhishNet Detector - phishing detection tool\n\n"
                + "Usage:\n"
                + "  java -jar phishnet.jar --url <url> [--json] [--config <path>]\n"
                + "  java -jar phishnet.jar --email <file.eml> [--json] [--config <path>]\n"
                + "  java -jar phishnet.jar --batch <file-of-urls> [--json] [--config <path>]\n\n"
                + "Options:\n"
                + "  --url <url>            Analyze a single URL\n"
                + "  --email <file.eml>     Analyze a single .eml email file\n"
                + "  --batch <file>         Analyze a newline-separated file of URLs ('#' comments allowed)\n"
                + "  --json                 Output machine-readable JSON instead of a human-readable report\n"
                + "  --config <path>        Use a custom YAML config instead of the bundled default\n"
                + "  --help, -h             Show this help message";
    }
}
