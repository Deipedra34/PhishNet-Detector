package com.phishnet.cli;

/** Parsed CLI arguments. Just string handling, no I/O, so it's straightforward to test. */
public record CliArgs(String url, String emailPath, String batchPath, String configPath,
                       boolean json, boolean help, boolean verbose, boolean quiet, boolean noColor) {

    /**
     * Parses raw CLI arguments.
     *
     * @throws IllegalArgumentException if the arguments are unrecognized, a flag is
     *                                   missing its required value, the mode flags
     *                                   ({@code --url}/{@code --email}/{@code --batch})
     *                                   are used incorrectly (none, or more than one),
     *                                   or both {@code --verbose} and {@code --quiet} are given
     */
    public static CliArgs parse(String[] args) {
        String url = null;
        String email = null;
        String batch = null;
        String configPath = null;
        boolean json = false;
        boolean help = false;
        boolean verbose = false;
        boolean quiet = false;
        boolean noColor = false;

        int i = 0;
        while (i < args.length) {
            String arg = args[i];
            switch (arg) {
                case "--url":
                    url = requireValue(args, ++i, arg);
                    break;
                case "--email":
                    email = requireValue(args, ++i, arg);
                    break;
                case "--batch":
                    batch = requireValue(args, ++i, arg);
                    break;
                case "--config":
                    configPath = requireValue(args, ++i, arg);
                    break;
                case "--json":
                    json = true;
                    break;
                case "--verbose":
                case "-v":
                    verbose = true;
                    break;
                case "--quiet":
                case "-q":
                    quiet = true;
                    break;
                case "--no-color":
                    noColor = true;
                    break;
                case "--help":
                case "-h":
                    help = true;
                    break;
                default:
                    throw new IllegalArgumentException("Unknown argument: " + arg);
            }
            i++;
        }

        if (verbose && quiet) {
            throw new IllegalArgumentException("Specify only one of --verbose or --quiet");
        }

        if (!help) {
            int modeCount = (url != null ? 1 : 0) + (email != null ? 1 : 0) + (batch != null ? 1 : 0);
            if (modeCount == 0) {
                throw new IllegalArgumentException("Specify one of --url, --email, or --batch");
            }
            if (modeCount > 1) {
                throw new IllegalArgumentException("Specify only one of --url, --email, or --batch");
            }
        }

        return new CliArgs(url, email, batch, configPath, json, help, verbose, quiet, noColor);
    }

    /** QUIET if --quiet, VERBOSE if --verbose, NORMAL otherwise. */
    public OutputLevel outputLevel() {
        if (quiet) {
            return OutputLevel.QUIET;
        }
        return verbose ? OutputLevel.VERBOSE : OutputLevel.NORMAL;
    }

    private static String requireValue(String[] args, int index, String flag) {
        if (index >= args.length) {
            throw new IllegalArgumentException(flag + " requires a value");
        }
        return args[index];
    }
}
