package com.phishnet.api;

import com.phishnet.i18n.Messages;

import java.util.List;
import java.util.Locale;

/**
 * Picks the language of a request's error messages and human-readable labels from
 * its {@code Accept-Language} header: the most preferred supported language (q-values
 * are honored), or English when the header is missing, malformed, or names nothing
 * supported. JSON keys and machine-readable values (levels, ids, statuses) stay English.
 */
final class ApiLanguage {

    static final String HEADER = "Accept-Language";

    private ApiLanguage() {
    }

    static Messages fromHeader(String header) {
        if (header == null || header.isBlank()) {
            return Messages.english();
        }
        List<Locale.LanguageRange> ranges;
        try {
            // Sorted by weight, most preferred first.
            ranges = Locale.LanguageRange.parse(header);
        } catch (IllegalArgumentException malformed) {
            return Messages.english();
        }
        for (Locale.LanguageRange range : ranges) {
            if (range.getWeight() <= 0) {
                continue;
            }
            String tag = range.getRange();
            if (tag.equals("*")) {
                return Messages.english();
            }
            String language = tag.split("-", 2)[0];
            if (Messages.isSupported(language)) {
                return Messages.forLocale(Locale.forLanguageTag(language));
            }
        }
        return Messages.english();
    }
}
