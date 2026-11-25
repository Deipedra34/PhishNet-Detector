package com.phishnet.i18n;

import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.MissingResourceException;
import java.util.ResourceBundle;
import java.util.concurrent.ConcurrentHashMap;

/**
 * User-facing text, from the {@value #BUNDLE} resource bundle: {@code messages.properties}
 * holds the English text (the default, and the fallback for anything missing) and
 * {@code messages_tr.properties} the Turkish. Both the CLI's own output and picocli's
 * help text come from it.
 *
 * <p>Placeholders are {@code {0}}, {@code {1}}, ... and are replaced as plain text - no
 * {@link java.text.MessageFormat} rules, so an apostrophe never needs escaping.
 */
public final class Messages {

    /** Base name of the bundle, under {@code src/main/resources/i18n/}. */
    public static final String BUNDLE = "i18n.messages";

    /** The languages with a translation, as ISO 639 codes; the first is the default. */
    public static final List<String> LANGUAGES = List.of("en", "tr");

    /**
     * Never falls back to the JVM's default locale: asking for English on a Turkish
     * system must give English (the base bundle), not Turkish.
     */
    private static final ResourceBundle.Control NO_DEFAULT_LOCALE_FALLBACK =
            ResourceBundle.Control.getNoFallbackControl(ResourceBundle.Control.FORMAT_PROPERTIES);

    private static final Map<Locale, Messages> CACHE = new ConcurrentHashMap<>();

    private static volatile Messages current;

    private final Locale locale;
    private final ResourceBundle bundle;

    private Messages(Locale locale, ResourceBundle bundle) {
        this.locale = locale;
        this.bundle = bundle;
    }

    /** The messages for {@code locale}'s language; English for anything without a translation. */
    public static Messages forLocale(Locale locale) {
        Locale language = Locale.forLanguageTag(locale.getLanguage());
        return CACHE.computeIfAbsent(language, l -> {
            ResourceBundle bundle = ResourceBundle.getBundle(BUNDLE, l, NO_DEFAULT_LOCALE_FALLBACK);
            // A language without its own file gets the base bundle, which is English.
            Locale effective = bundle.getLocale().getLanguage().isEmpty() ? Locale.ENGLISH : bundle.getLocale();
            return new Messages(effective, bundle);
        });
    }

    /** Whether {@code language} (an ISO 639 code such as "tr") has a translation. */
    public static boolean isSupported(String language) {
        return language != null && LANGUAGES.contains(language.toLowerCase(Locale.ROOT));
    }

    public static Messages english() {
        return forLocale(Locale.ENGLISH);
    }

    /**
     * The messages the CLI is currently printing in. English until the CLI entry point
     * picks a language for the run.
     */
    public static Messages current() {
        Messages messages = current;
        return messages != null ? messages : english();
    }

    public static void setCurrent(Messages messages) {
        current = messages;
    }

    /** {@code current().get(key, args)}: the text in the language the CLI is printing in. */
    public static String text(String key, Object... args) {
        return current().get(key, args);
    }

    /** The bundle itself, for picocli's help text. */
    public ResourceBundle bundle() {
        return bundle;
    }

    /** The language these messages are in: {@code en} or {@code tr}. */
    public Locale locale() {
        return locale;
    }

    /**
     * The text for {@code key}, with {@code {0}}, {@code {1}}, ... replaced by {@code args}.
     * A {@link Localized} argument is rendered in this language too.
     *
     * @throws MissingResourceException if no bundle (not even the English one) has the key
     */
    public String get(String key, Object... args) {
        String text = bundle.getString(key);
        if (args.length == 0 || text.indexOf('{') < 0) {
            return text;
        }
        // One pass, so a "{1}" inside an argument (say, an email subject) is left alone.
        StringBuilder out = new StringBuilder(text.length() + 32);
        int i = 0;
        while (i < text.length()) {
            char c = text.charAt(i);
            int close = c == '{' ? text.indexOf('}', i) : -1;
            int index = close > i + 1 && close <= i + 3 ? placeholderIndex(text.substring(i + 1, close)) : -1;
            if (index >= 0 && index < args.length) {
                Object arg = args[index];
                out.append(arg instanceof Localized localized ? localized.in(this) : arg);
                i = close + 1;
            } else {
                out.append(c);
                i++;
            }
        }
        return out.toString();
    }

    private static int placeholderIndex(String digits) {
        for (int i = 0; i < digits.length(); i++) {
            if (digits.charAt(i) < '0' || digits.charAt(i) > '9') {
                return -1;
            }
        }
        return Integer.parseInt(digits);
    }

    /** {@code key + ".one"} when {@code count} is 1, otherwise {@code key + ".other"}. */
    public String plural(String key, long count, Object... args) {
        Object[] all = new Object[args.length + 1];
        all[0] = count;
        System.arraycopy(args, 0, all, 1, args.length);
        return get(key + (count == 1 ? ".one" : ".other"), all);
    }

    public boolean has(String key) {
        return bundle.containsKey(key);
    }

    @Override
    public String toString() {
        return "Messages[" + locale + "]";
    }
}
