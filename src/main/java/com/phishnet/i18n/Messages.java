package com.phishnet.i18n;

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
     *
     * @throws MissingResourceException if no bundle (not even the English one) has the key
     */
    public String get(String key, Object... args) {
        String text = bundle.getString(key);
        for (int i = 0; i < args.length; i++) {
            text = text.replace("{" + i + "}", String.valueOf(args[i]));
        }
        return text;
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
