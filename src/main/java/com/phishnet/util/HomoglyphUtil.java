package com.phishnet.util;

import java.lang.Character.UnicodeScript;
import java.net.IDN;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

/**
 * Homograph/IDN-homoglyph helpers - catching domains that use look-alike
 * characters from another script (usually Cyrillic or Greek) to mimic a
 * real brand, e.g. an all-Cyrillic "apple.com" that reads identically to
 * the real thing.
 */
public final class HomoglyphUtil {

    /** Cyrillic/Greek/misc characters mapped to the Latin letter they mimic. Not exhaustive, just the common ones. */
    private static final Map<Character, Character> CONFUSABLES = buildConfusableMap();

    private HomoglyphUtil() {
    }

    private static Map<Character, Character> buildConfusableMap() {
        Map<Character, Character> map = new HashMap<>();
        // Cyrillic lookalikes
        put(map, 'а', 'a');
        put(map, 'ь', 'b');
        put(map, 'с', 'c');
        put(map, 'е', 'e');
        put(map, 'ԁ', 'd');
        put(map, 'ѕ', 's');
        put(map, 'і', 'i');
        put(map, 'ј', 'j');
        put(map, 'к', 'k');
        put(map, 'о', 'o');
        put(map, 'р', 'p');
        put(map, 'ԛ', 'q');
        put(map, 'г', 'r');
        put(map, 'т', 't');
        put(map, 'у', 'y');
        put(map, 'х', 'x');
        put(map, 'ѡ', 'w');
        put(map, 'ѵ', 'v');
        put(map, 'ᴦ', 'r');
        put(map, 'ⅰ', 'i');
        put(map, 'ⅼ', 'l');
        put(map, 'ӏ', 'l'); // Cyrillic palochka - commonly substituted for Latin lowercase "l"
        // Greek lookalikes
        put(map, 'α', 'a');
        put(map, 'ο', 'o');
        put(map, 'ρ', 'p');
        put(map, 'υ', 'u');
        put(map, 'κ', 'k');
        put(map, 'ν', 'v');
        put(map, 'χ', 'x');
        put(map, 'ι', 'i');
        put(map, 'β', 'b');
        put(map, 'η', 'n');
        return map;
    }

    private static void put(Map<Character, Character> map, char confusable, char latin) {
        map.put(confusable, latin);
    }

    /** Decodes punycode labels (xn--...) back to Unicode; leaves anything else as-is. */
    public static String decodeHost(String host) {
        if (host == null || host.isEmpty()) {
            return host;
        }
        try {
            return IDN.toUnicode(host, IDN.ALLOW_UNASSIGNED);
        } catch (IllegalArgumentException e) {
            return host;
        }
    }

    /** True if any label in the host starts with xn--. */
    public static boolean containsPunycodeLabel(String host) {
        if (host == null) return false;
        for (String label : host.split("\\.")) {
            if (label.toLowerCase(Locale.ROOT).startsWith("xn--")) {
                return true;
            }
        }
        return false;
    }

    /**
     * True if the text mixes two or more Unicode scripts (ignoring digits/
     * punctuation/combining marks). A pure-Latin or pure-Cyrillic label comes
     * back false; something like Latin "ppl" spliced with a Cyrillic "o"
     * comes back true - that splice is basically the signature of a
     * partial-substitution homograph attack.
     */
    public static boolean isMixedScript(String text) {
        if (text == null || text.isEmpty()) {
            return false;
        }
        UnicodeScript found = null;
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (!Character.isLetter(c)) {
                continue;
            }
            UnicodeScript script = UnicodeScript.of(c);
            if (script == UnicodeScript.COMMON || script == UnicodeScript.INHERITED
                    || script == UnicodeScript.UNKNOWN) {
                continue;
            }
            if (found == null) {
                found = script;
            } else if (found != script) {
                return true;
            }
        }
        return false;
    }

    /**
     * Decodes punycode, swaps every confusable char for its Latin equivalent,
     * lower-cases the result. Compare this "skeleton" against a plain brand
     * name to catch a fully non-Latin look-alike (an all-Cyrillic domain is
     * single-script, so isMixedScript alone won't flag it).
     */
    public static String toAsciiSkeleton(String hostOrLabel) {
        String decoded = decodeHost(hostOrLabel);
        StringBuilder sb = new StringBuilder(decoded.length());
        for (int i = 0; i < decoded.length(); i++) {
            char c = decoded.charAt(i);
            Character mapped = CONFUSABLES.get(c);
            sb.append(mapped != null ? mapped : c);
        }
        return sb.toString().toLowerCase(Locale.ROOT);
    }
}
