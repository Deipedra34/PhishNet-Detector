package com.phishnet.cli;

import com.phishnet.history.HistoryDatabase;
import com.phishnet.history.HistoryEntry;
import com.phishnet.history.HistoryFilter;
import com.phishnet.model.RiskLevel;
import com.phishnet.util.ColorSupport;
import picocli.CommandLine;
import picocli.CommandLine.ArgGroup;
import picocli.CommandLine.Command;
import picocli.CommandLine.ITypeConverter;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Option;
import picocli.CommandLine.ParameterException;
import picocli.CommandLine.Spec;
import picocli.CommandLine.TypeConversionException;

import java.io.PrintStream;
import java.nio.file.Path;
import java.sql.SQLException;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneId;
import java.time.format.DateTimeParseException;
import java.util.List;
import java.util.concurrent.Callable;

/**
 * {@code phishnet history list|search|stats}: read-only queries over the SQLite scan
 * history ({@link HistoryDatabase}). Like {@code serve}, {@link Main#run} hands it the
 * arguments after "history", so normal scan parsing is untouched.
 *
 * Output follows the scan output conventions (see {@link HistoryReporter}):
 * {@code --quiet}/{@code --verbose}, colored risk levels, {@code --no-color}.
 */
@Command(
        name = "phishnet " + Main.HISTORY_COMMAND,
        resourceBundle = Main.MESSAGES_BUNDLE,
        mixinStandardHelpOptions = true,
        versionProvider = Main.VersionProvider.class,
        sortOptions = false,
        descriptionHeading = "%n")
final class HistoryCommand implements Callable<Integer> {

    @Spec
    private CommandSpec spec;

    @Override
    public Integer call() {
        throw new ParameterException(spec.commandLine(), "Missing required command: list, search, or stats");
    }

    /** The {@code history} command with its subcommands wired to the given streams. */
    static CommandLine commandLine(PrintStream out, PrintStream err) {
        ZoneId zone = ZoneId.systemDefault();
        CommandLine cmd = new CommandLine(new HistoryCommand());
        cmd.addSubcommand("list", new ListCommand(out, err, zone));
        cmd.addSubcommand("search", new SearchCommand(out, err, zone));
        cmd.addSubcommand("stats", new StatsCommand(out, err, zone));
        // Lets "--risk high" and "--type email" work as well as the upper-case names.
        cmd.setCaseInsensitiveEnumValuesAllowed(true);
        return cmd;
    }

    /** Options and error handling shared by every history subcommand. */
    abstract static class QueryCommand implements Callable<Integer> {

        @Spec
        CommandSpec spec;

        @Option(names = "--history-db", paramLabel = "<path>")
        String databasePath;

        @Option(names = "--no-color")
        boolean noColor;

        @ArgGroup(exclusive = true, multiplicity = "0..1", heading = "%n")
        Verbosity verbosity = new Verbosity();

        static final class Verbosity {
            @Option(names = {"--verbose", "-v"})
            boolean verbose;

            @Option(names = {"--quiet", "-q"})
            boolean quiet;
        }

        private final PrintStream out;
        private final PrintStream err;
        private final ZoneId zone;

        QueryCommand(PrintStream out, PrintStream err, ZoneId zone) {
            this.out = out;
            this.err = err;
            this.zone = zone;
        }

        @Override
        public final Integer call() {
            validate();
            Path file = databasePath != null ? Path.of(databasePath) : HistoryDatabase.defaultPath();
            // Read-only use: writes stay disabled, and nothing is created if the file is missing.
            HistoryDatabase database = new HistoryDatabase(file, false, err);
            HistoryReporter reporter = new HistoryReporter(out, outputLevel(), ColorSupport.isEnabled(noColor), zone);
            try {
                run(database, reporter);
                return 0;
            } catch (SQLException | RuntimeException e) {
                err.println("Error: could not read scan history database " + file + ": " + e.getMessage());
                return 1;
            }
        }

        /** Rejects option combinations picocli can't check on its own; throws a usage error. */
        void validate() {
        }

        abstract void run(HistoryDatabase database, HistoryReporter reporter) throws SQLException;

        ZoneId zone() {
            return zone;
        }

        ParameterException usageError(String message) {
            return new ParameterException(spec.commandLine(), message);
        }

        void requireNonNegative(String option, int value) {
            if (value < 0) {
                throw usageError("Invalid value for option '" + option + "': " + value + " (must be 0 or more)");
            }
        }

        private OutputLevel outputLevel() {
            if (verbosity.quiet) {
                return OutputLevel.QUIET;
            }
            return verbosity.verbose ? OutputLevel.VERBOSE : OutputLevel.NORMAL;
        }
    }

    @Command(
            name = "list",
            mixinStandardHelpOptions = true,
            versionProvider = Main.VersionProvider.class,
            sortOptions = false,
            descriptionHeading = "%n")
    static final class ListCommand extends QueryCommand {

        @Option(names = "--limit", paramLabel = "<n>", defaultValue = "20")
        int limit;

        ListCommand(PrintStream out, PrintStream err, ZoneId zone) {
            super(out, err, zone);
        }

        @Override
        void validate() {
            requireNonNegative("--limit", limit);
        }

        @Override
        void run(HistoryDatabase database, HistoryReporter reporter) throws SQLException {
            List<HistoryEntry> entries = database.search(HistoryFilter.recent(limit));
            reporter.printEntries(entries, database.file(), "No scans recorded yet");
        }
    }

    @Command(
            name = "search",
            mixinStandardHelpOptions = true,
            versionProvider = Main.VersionProvider.class,
            sortOptions = false,
            descriptionHeading = "%n")
    static final class SearchCommand extends QueryCommand {

        @Option(names = "--target", paramLabel = "<text>")
        String target;

        @Option(names = "--risk", paramLabel = "<level>")
        RiskLevel risk;

        @Option(names = "--type", paramLabel = "<type>")
        HistoryWriter.TargetType type;

        @Option(names = "--since", paramLabel = "<YYYY-MM-DD>", converter = DateConverter.class)
        LocalDate since;

        @Option(names = "--until", paramLabel = "<YYYY-MM-DD>", converter = DateConverter.class)
        LocalDate until;

        @Option(names = "--limit", paramLabel = "<n>", defaultValue = "20")
        int limit;

        SearchCommand(PrintStream out, PrintStream err, ZoneId zone) {
            super(out, err, zone);
        }

        @Override
        void validate() {
            requireNonNegative("--limit", limit);
            if (since != null && until != null && since.isAfter(until)) {
                throw usageError("--since (" + since + ") must not be after --until (" + until + ")");
            }
        }

        @Override
        void run(HistoryDatabase database, HistoryReporter reporter) throws SQLException {
            // Whole local days: --since from its first instant, --until up to (not including)
            // the first instant of the following day.
            Instant from = since == null ? null : since.atStartOfDay(zone()).toInstant();
            Instant to = until == null ? null : until.plusDays(1).atStartOfDay(zone()).toInstant();
            String text = target == null ? null : target.trim();
            HistoryFilter filter = new HistoryFilter(text, risk, type, from, to, limit);
            reporter.printEntries(database.search(filter), database.file(), "No matching scans");
        }
    }

    @Command(
            name = "stats",
            mixinStandardHelpOptions = true,
            versionProvider = Main.VersionProvider.class,
            sortOptions = false,
            descriptionHeading = "%n")
    static final class StatsCommand extends QueryCommand {

        @Option(names = "--top", paramLabel = "<n>", defaultValue = "10")
        int top;

        StatsCommand(PrintStream out, PrintStream err, ZoneId zone) {
            super(out, err, zone);
        }

        @Override
        void validate() {
            requireNonNegative("--top", top);
        }

        @Override
        void run(HistoryDatabase database, HistoryReporter reporter) throws SQLException {
            reporter.printStats(database.stats(top), database.file());
        }
    }

    /** Parses {@code YYYY-MM-DD}, with a clearer message than the generic conversion error. */
    static final class DateConverter implements ITypeConverter<LocalDate> {
        @Override
        public LocalDate convert(String value) {
            try {
                return LocalDate.parse(value);
            } catch (DateTimeParseException e) {
                throw new TypeConversionException("'" + value + "' is not a date in YYYY-MM-DD format");
            }
        }
    }
}
