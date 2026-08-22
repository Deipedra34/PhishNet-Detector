package com.phishnet.util;

/**
 * Standard edit-distance calc, used by UrlAnalyzer to catch typosquatted
 * domains against the brand list.
 */
public final class LevenshteinDistance {

    private LevenshteinDistance() {
    }

    /** Minimum number of single-char inserts/deletes/substitutions to turn a into b. */
    public static int distance(String a, String b) {
        if (a == null) a = "";
        if (b == null) b = "";
        int n = a.length();
        int m = b.length();
        if (n == 0) return m;
        if (m == 0) return n;

        int[] previous = new int[m + 1];
        int[] current = new int[m + 1];
        for (int j = 0; j <= m; j++) {
            previous[j] = j;
        }

        for (int i = 1; i <= n; i++) {
            current[0] = i;
            char ca = a.charAt(i - 1);
            for (int j = 1; j <= m; j++) {
                char cb = b.charAt(j - 1);
                int cost = (ca == cb) ? 0 : 1;
                int deletion = previous[j] + 1;
                int insertion = current[j - 1] + 1;
                int substitution = previous[j - 1] + cost;
                current[j] = Math.min(Math.min(deletion, insertion), substitution);
            }
            int[] tmp = previous;
            previous = current;
            current = tmp;
        }
        return previous[m];
    }
}
