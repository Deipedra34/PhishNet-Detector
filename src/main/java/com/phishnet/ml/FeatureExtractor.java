package com.phishnet.ml;

import com.phishnet.model.DomainAgeResult;
import com.phishnet.model.PhishNetConfig;
import com.phishnet.model.Signal;
import com.phishnet.model.UrlAnalysisResult;
import com.phishnet.model.UrlComponents;
import com.phishnet.util.LevenshteinDistance;

import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Turns what {@code UrlAnalyzer} and {@code DomainAgeChecker} already produced for a
 * URL into a {@link FeatureVector}. Nothing is re-parsed or re-detected: the flags
 * come from the signal ids, the counts from the parsed {@link UrlComponents}, and the
 * age from the WHOIS result. The one extra computation is {@code brand_distance}, a
 * plain number the analyzer only uses internally (to decide the typosquatting flag).
 *
 * No I/O; safe to call on any analysis result, including a malformed URL's (whose
 * features are then mostly zeros - see {@link #canExtract}).
 */
public final class FeatureExtractor {

    /** {@code brand_distance} for domains with no near brand match, IP hosts, and exact brand matches. */
    public static final int BRAND_DISTANCE_CAP = 10;

    private final List<String> brands;

    public FeatureExtractor(PhishNetConfig config) {
        this.brands = config.brands().stream()
                .map(b -> b.toLowerCase(Locale.ROOT))
                .collect(Collectors.toList());
    }

    /** False for a URL with no usable host (malformed or empty input), which the ML layer skips. */
    public static boolean canExtract(UrlAnalysisResult result) {
        return !result.components().host().isEmpty();
    }

    public FeatureVector extract(UrlAnalysisResult result, DomainAgeResult domainAge) {
        UrlComponents c = result.components();
        Set<String> signalIds = result.signals().stream().map(Signal::id).collect(Collectors.toSet());

        double[] v = new double[FeatureVector.SIZE];
        v[0] = c.rawUrl().length();
        v[1] = specialCharCount(c.rawUrl());
        v[2] = c.host().chars().filter(ch -> ch == '.').count();
        // For an IP host the analyzer stores the whole address as the "subdomain".
        v[3] = c.isIpHost() || c.subdomain().isEmpty() ? 0 : c.subdomain().split("\\.").length;
        v[4] = flag(c.isIpHost());
        v[5] = brandDistance(c);
        v[6] = flag(signalIds.contains("typosquatting"));
        v[7] = flag(signalIds.contains("homograph"));
        v[8] = flag(signalIds.contains("suspiciousTld"));
        v[9] = flag(signalIds.contains("urlShortener"));
        v[10] = domainAge != null && domainAge.isKnown() ? domainAge.ageDays() : Double.NaN;
        v[11] = flag("https".equalsIgnoreCase(c.scheme()));
        return new FeatureVector(v);
    }

    /**
     * Characters other than letters, digits, and the structural {@code . : /} -
     * e.g. {@code - _ @ ? = & % ~}. Phishing URLs tend to pile these up.
     */
    static int specialCharCount(String url) {
        int count = 0;
        for (int i = 0; i < url.length(); i++) {
            char ch = url.charAt(i);
            if (!Character.isLetterOrDigit(ch) && ch != '.' && ch != ':' && ch != '/') {
                count++;
            }
        }
        return count;
    }

    /**
     * How close the domain comes to impersonating a configured brand: the smallest
     * edit distance between any {@code -}/{@code _}-separated segment of the domain and
     * a brand, capped at {@link #BRAND_DISTANCE_CAP}. {@code paypa1} scores 1 and
     * {@code paypal-secure-login} 0 (it contains the brand outright). The brand's own
     * domain ({@code paypal.com}) is the real thing, not a look-alike, so it gets the cap.
     */
    int brandDistance(UrlComponents c) {
        String domain = c.domain().toLowerCase(Locale.ROOT);
        if (c.isIpHost() || domain.isEmpty() || brands.contains(domain)) {
            return BRAND_DISTANCE_CAP;
        }
        int best = BRAND_DISTANCE_CAP;
        for (String segment : domain.split("[-_]")) {
            if (segment.isEmpty()) {
                continue;
            }
            for (String brand : brands) {
                best = Math.min(best, LevenshteinDistance.distance(segment, brand));
            }
        }
        return best;
    }

    private static double flag(boolean b) {
        return b ? 1 : 0;
    }
}
