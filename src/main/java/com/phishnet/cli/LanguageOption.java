package com.phishnet.cli;

import com.phishnet.i18n.Messages;
import picocli.CommandLine;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Model.OptionSpec;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

/**
 * The global {@code --lang <en|tr>} option, accepted by every command. It is read
 * before anything is parsed - the help text depends on it, and it may come before a
 * subcommand name ({@code phishnet --lang tr serve}) - and taken out of the arguments,
 * so every command parses the rest exactly as it would without it.
 *
 * <p>Without {@code --lang} the system language is used when there is a translation
 * for it, otherwise English. An unsupported {@code --lang} value falls back to English
 * with a warning.
 */
final class LanguageOption {

    static final String NAME = "--lang";

    private LanguageOption() {
    }

    /**
     * @param messages         the language to print in
     * @param unsupportedValue the {@code --lang} value given, if it isn't a supported language; otherwise null
     * @param remainingArgs    the arguments without {@code --lang} and its value
     */
    record Selection(Messages messages, String unsupportedValue, String[] remainingArgs) {
    }

    static Selection select(String[] args, Locale systemLocale) {
        String value = null;
        List<String> rest = new ArrayList<>(args.length);
        for (int i = 0; i < args.length; i++) {
            String arg = args[i];
            if (arg.equals("--")) {
                // Everything after "--" is a positional value, never an option.
                rest.addAll(Arrays.asList(args).subList(i, args.length));
                break;
            }
            if (arg.startsWith(NAME + "=")) {
                value = arg.substring(NAME.length() + 1);
            } else if (arg.equals(NAME) && i + 1 < args.length && !args[i + 1].startsWith("-")) {
                value = args[++i];
            } else {
                // Includes a bare trailing "--lang", left for picocli to report as missing its value.
                rest.add(arg);
            }
        }
        String[] remaining = rest.toArray(String[]::new);
        if (value == null) {
            return new Selection(Messages.forLocale(systemLocale), null, remaining);
        }
        String language = Locale.forLanguageTag(value.trim().replace('_', '-')).getLanguage();
        return Messages.isSupported(language)
                ? new Selection(Messages.forLocale(Locale.forLanguageTag(language)), null, remaining)
                : new Selection(Messages.english(), value, remaining);
    }

    /**
     * Adds {@code --lang} to {@code cmd} and its subcommands, just before {@code --help}
     * and {@code --version}, so it is listed in their help and accepted by their parsers.
     */
    static void addTo(CommandLine cmd) {
        CommandSpec spec = cmd.getCommandSpec();
        if (spec.findOption(NAME) == null) {
            List<OptionSpec> standardHelp = spec.options().stream()
                    .filter(option -> option.usageHelp() || option.versionHelp())
                    .toList();
            standardHelp.forEach(spec::remove);
            spec.addOption(OptionSpec.builder(NAME)
                    .paramLabel("<lang>")
                    .type(String.class)
                    .descriptionKey("lang")
                    .build());
            standardHelp.forEach(spec::addOption);
        }
        cmd.getSubcommands().values().forEach(LanguageOption::addTo);
    }
}
