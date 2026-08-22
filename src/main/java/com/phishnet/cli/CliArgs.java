package com.phishnet.cli;

/** Parsed CLI arguments. Just string handling, no I/O, so it's straightforward to test. */
public record CliArgs(String url, String emailPath, String batchPath, String configPath,
                       boolean json, boolean help) {

    /**
     * Parses raw CLI arguments.
     *
     * @throws IllegalArgumentException if the arguments are unrecognized, a flag is
     *                                   missing its required value, or the mode flags
     *                                   ({@code --url}/{@code --email}/{@code --batch})
     *                                   are used incorrectly (none, or more than one)
     */
    public static CliArgs parse(String[] args) {
        String url = null;
        String email = null;
        String batch = null;
        String configPath = null;
        boolean json = false;
        boolean help = false;

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
                case "--help":
                case "-h":
                    help = true;
                    break;
                default:
                    throw new IllegalArgumentException("Unknown argument: " + arg);
            }
            i++;
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

        return new CliArgs(url, email, batch, configPath, json, help);
    }

    private static String requireValue(String[] args, int index, String flag) {
        if (index >= args.length) {
            throw new IllegalArgumentException(flag + " requires a value");
        }
        return args[index];
    }
}
