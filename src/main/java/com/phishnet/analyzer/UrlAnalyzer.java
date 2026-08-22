package com.phishnet.analyzer;

import com.phishnet.model.PhishNetConfig;
import com.phishnet.model.Signal;
import com.phishnet.model.SignalCategory;
import com.phishnet.model.UrlAnalysisResult;
import com.phishnet.model.UrlComponents;
import com.phishnet.util.HomoglyphUtil;
import com.phishnet.util.LevenshteinDistance;

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URLDecoder;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Breaks a URL down into its parts and checks it for the usual phishing
 * red flags: homograph/punycode tricks, brand typosquatting, shorteners,
 * bad TLDs, raw IP hosts, and overly long or obfuscated URLs.
 *
 * No DNS lookups, no network calls - just string parsing, so it's safe to
 * throw untrusted URLs at it in bulk. Brand list, TLD list etc. all come
 * from the injected config.
 */
public final class UrlAnalyzer {

    private static final Pattern IPV4_PATTERN = Pattern.compile(
            "^(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})$");
    private static final Pattern PERCENT_ENCODED_PATTERN = Pattern.compile("%[0-9A-Fa-f]{2}");
    private static final Pattern EMBEDDED_URL_PATTERN = Pattern.compile(
            "https?(?:%3A%2F%2F|://)", Pattern.CASE_INSENSITIVE);

    /** Known two-label public suffixes; anything else assumes the last label alone is the TLD. */
    private static final Set<String> TWO_LABEL_SUFFIXES = Set.of(
            "co.uk", "org.uk", "gov.uk", "ac.uk", "co.jp", "co.kr", "co.in",
            "com.au", "com.br", "com.tr", "com.mx", "com.cn", "net.au");

    private final PhishNetConfig config;

    public UrlAnalyzer(PhishNetConfig config) {
        this.config = config;
    }

    /**
     * Parses and analyzes one URL. Bad input never throws - you get a
     * "malformedUrl" signal back and mostly-empty components instead, so
     * batch mode can keep going through the rest of the list.
     */
    public UrlAnalysisResult analyze(String rawInput) {
        String raw = rawInput == null ? "" : rawInput.trim();
        List<Signal> signals = new ArrayList<>();

        if (raw.isEmpty()) {
            signals.add(malformed("URL is empty"));
            return new UrlAnalysisResult(emptyComponents(rawInput == null ? "" : rawInput), signals);
        }

        URI uri;
        try {
            uri = toUri(raw);
        } catch (URISyntaxException e) {
            signals.add(malformed("Could not parse URL: " + e.getMessage()));
            return new UrlAnalysisResult(emptyComponents(raw), signals);
        }

        String host = uri.getHost();
        int port = uri.getPort();
        if (host == null) {
            // URI.getHost() comes back null for a raw Unicode authority (not punycode-encoded) -
            // happens with homograph domains typed in plain UTF-8. Parse it by hand instead.
            host = hostFromAuthority(uri.getRawAuthority());
            port = portFromAuthority(uri.getRawAuthority(), -1);
        }
        if (host == null || host.isEmpty()) {
            signals.add(malformed("URL has no resolvable host"));
            return new UrlAnalysisResult(emptyComponents(raw), signals);
        }
        host = host.toLowerCase(Locale.ROOT);

        boolean ipHost = isIpAddress(host);
        String[] split = splitHost(host, ipHost);
        String subdomain = split[0];
        String domain = split[1];
        String tld = split[2];

        Map<String, List<String>> queryParams = parseQueryParams(uri.getRawQuery());

        UrlComponents components = new UrlComponents(
                raw,
                uri.getScheme() == null ? "" : uri.getScheme(),
                host,
                port,
                subdomain,
                domain,
                tld,
                uri.getRawPath() == null ? "" : uri.getRawPath(),
                uri.getFragment() == null ? "" : uri.getFragment(),
                queryParams,
                ipHost);

        signals.addAll(detectIpAddressHost(components));
        signals.addAll(detectSuspiciousTld(components));
        signals.addAll(detectUrlShortener(components));
        signals.addAll(detectHomograph(components));
        signals.addAll(detectTyposquatting(components));
        signals.addAll(detectLongOrObfuscatedUrl(components));

        return new UrlAnalysisResult(components, signals);
    }

    // --- parsing helpers -------------------------------------------------

    private static URI toUri(String raw) throws URISyntaxException {
        String candidate = hasScheme(raw) ? raw : "http://" + raw;
        return new URI(candidate);
    }

    /**
     * True if s looks like it starts with a URI scheme (http:, mailto:, ...).
     * Scheme names never have a dot, so "example.com:8080" (host:port, no
     * scheme) doesn't get confused with "mailto:user@example.com".
     */
    private static boolean hasScheme(String s) {
        int colon = s.indexOf(':');
        if (colon <= 0 || !Character.isLetter(s.charAt(0))) {
            return false;
        }
        for (int i = 0; i < colon; i++) {
            char c = s.charAt(i);
            if (!(Character.isLetterOrDigit(c) || c == '+' || c == '-')) {
                return false;
            }
        }
        return true;
    }

    /** Fallback host extraction for when URI.getHost() gives up (non-ACE international hostnames). */
    private static String hostFromAuthority(String rawAuthority) {
        if (rawAuthority == null) {
            return null;
        }
        String authority = rawAuthority;
        int at = authority.lastIndexOf('@');
        if (at >= 0) {
            authority = authority.substring(at + 1);
        }
        if (authority.startsWith("[")) {
            int close = authority.indexOf(']');
            return close >= 0 ? authority.substring(0, close + 1) : authority;
        }
        int colon = authority.lastIndexOf(':');
        if (colon >= 0 && isAllDigits(authority.substring(colon + 1))) {
            return authority.substring(0, colon);
        }
        return authority;
    }

    private static int portFromAuthority(String rawAuthority, int fallback) {
        if (rawAuthority == null) {
            return fallback;
        }
        String authority = rawAuthority;
        int at = authority.lastIndexOf('@');
        if (at >= 0) {
            authority = authority.substring(at + 1);
        }
        int searchFrom = authority.startsWith("[") ? authority.indexOf(']') : 0;
        int colon = searchFrom >= 0 ? authority.indexOf(':', searchFrom) : -1;
        if (colon >= 0 && isAllDigits(authority.substring(colon + 1))) {
            try {
                return Integer.parseInt(authority.substring(colon + 1));
            } catch (NumberFormatException ignored) {
                return fallback;
            }
        }
        return fallback;
    }

    private static boolean isAllDigits(String s) {
        return !s.isEmpty() && s.chars().allMatch(Character::isDigit);
    }

    private static UrlComponents emptyComponents(String raw) {
        return new UrlComponents(raw, "", "", -1, "", "", "", "", "", new LinkedHashMap<>(), false);
    }

    private static Signal malformed(String detail) {
        return new Signal("malformedUrl", SignalCategory.URL, "URL is malformed or unparseable", detail);
    }

    private static boolean isIpAddress(String host) {
        String h = host;
        if (h.startsWith("[") && h.endsWith("]")) {
            return true; // bracketed IPv6 literal
        }
        Matcher m = IPV4_PATTERN.matcher(h);
        if (!m.matches()) {
            return false;
        }
        for (int i = 1; i <= 4; i++) {
            int octet = Integer.parseInt(m.group(i));
            if (octet > 255) {
                return false;
            }
        }
        return true;
    }

    /** [subdomain, domain, tld]. For an IP host, domain/tld come back empty and subdomain is the whole thing. */
    private static String[] splitHost(String host, boolean ipHost) {
        if (ipHost) {
            return new String[]{host, "", ""};
        }
        String[] labels = host.split("\\.");
        if (labels.length == 1) {
            return new String[]{"", labels[0], ""};
        }
        String lastTwo = labels[labels.length - 2] + "." + labels[labels.length - 1];
        int tldLabelCount = TWO_LABEL_SUFFIXES.contains(lastTwo) ? 2 : 1;

        if (labels.length <= tldLabelCount) {
            return new String[]{"", "", host};
        }

        String tld = String.join(".", java.util.Arrays.copyOfRange(labels, labels.length - tldLabelCount, labels.length));
        int domainIndex = labels.length - tldLabelCount - 1;
        String domain = labels[domainIndex];
        String subdomain = domainIndex > 0
                ? String.join(".", java.util.Arrays.copyOfRange(labels, 0, domainIndex))
                : "";
        return new String[]{subdomain, domain, tld};
    }

    private static Map<String, List<String>> parseQueryParams(String rawQuery) {
        Map<String, List<String>> params = new LinkedHashMap<>();
        if (rawQuery == null || rawQuery.isEmpty()) {
            return params;
        }
        for (String pair : rawQuery.split("&")) {
            if (pair.isEmpty()) {
                continue;
            }
            int eq = pair.indexOf('=');
            String key = eq >= 0 ? pair.substring(0, eq) : pair;
            String value = eq >= 0 ? pair.substring(eq + 1) : "";
            params.computeIfAbsent(decode(key), k -> new ArrayList<>()).add(decode(value));
        }
        return params;
    }

    private static String decode(String s) {
        try {
            return URLDecoder.decode(s, StandardCharsets.UTF_8.name());
        } catch (UnsupportedEncodingException | IllegalArgumentException e) {
            return s;
        }
    }

    // --- detectors ---------------------------------------------------------

    private List<Signal> detectIpAddressHost(UrlComponents c) {
        if (!c.isIpHost()) {
            return List.of();
        }
        return List.of(new Signal("ipAddressHost", SignalCategory.URL,
                "URL uses a raw IP address instead of a domain name", c.host()));
    }

    private List<Signal> detectSuspiciousTld(UrlComponents c) {
        if (c.isIpHost() || c.tld().isEmpty()) {
            return List.of();
        }
        String tld = c.tld().toLowerCase(Locale.ROOT);
        for (String suspicious : config.suspiciousTlds()) {
            if (tld.equals(suspicious.toLowerCase(Locale.ROOT))) {
                return List.of(new Signal("suspiciousTld", SignalCategory.URL,
                        "URL uses a TLD commonly abused for phishing", "." + tld));
            }
        }
        return List.of();
    }

    private List<Signal> detectUrlShortener(UrlComponents c) {
        if (c.isIpHost()) {
            return List.of();
        }
        String registrable = c.registrableDomain().toLowerCase(Locale.ROOT);
        for (String shortener : config.urlShorteners()) {
            if (registrable.equals(shortener.toLowerCase(Locale.ROOT))) {
                return List.of(new Signal("urlShortener", SignalCategory.URL,
                        "URL uses a link-shortening service, which hides the real destination",
                        registrable));
            }
        }
        return List.of();
    }

    private List<Signal> detectHomograph(UrlComponents c) {
        if (c.isIpHost() || c.host().isEmpty()) {
            return List.of();
        }

        // Only look at subdomain/domain labels, not the TLD - plenty of legit IDN sites
        // have an ASCII TLD with a non-Latin domain. What we actually care about is
        // script mixing *within* a single label.
        List<String> labels = new ArrayList<>();
        if (!c.subdomain().isEmpty()) {
            for (String label : c.subdomain().split("\\.")) {
                labels.add(label);
            }
        }
        if (!c.domain().isEmpty()) {
            labels.add(c.domain());
        }

        boolean anySuspicious = labels.stream().anyMatch(
                l -> HomoglyphUtil.containsPunycodeLabel(l) || l.chars().anyMatch(ch -> ch > 127));
        if (!anySuspicious) {
            return List.of();
        }

        for (String label : labels) {
            String decodedLabel = HomoglyphUtil.decodeHost(label);
            if (HomoglyphUtil.isMixedScript(decodedLabel)) {
                return List.of(new Signal("homograph", SignalCategory.URL,
                        "Domain label mixes character scripts, a common homograph/IDN spoofing technique",
                        decodedLabel));
            }
        }

        String decodedDomain = HomoglyphUtil.decodeHost(c.domain());
        String skeleton = HomoglyphUtil.toAsciiSkeleton(decodedDomain);
        for (String brand : config.brands()) {
            String normalizedBrand = brand.toLowerCase(Locale.ROOT);
            if (skeleton.equals(normalizedBrand)) {
                return List.of(new Signal("homograph", SignalCategory.URL,
                        "Domain uses look-alike characters to visually mimic brand '" + brand + "'",
                        HomoglyphUtil.decodeHost(c.host())));
            }
        }
        // Punycode/non-ASCII with no brand match is still unusual for a legitimate site.
        return List.of(new Signal("homograph", SignalCategory.URL,
                "Domain contains internationalized/punycode-encoded characters",
                HomoglyphUtil.decodeHost(c.host())));
    }

    private List<Signal> detectTyposquatting(UrlComponents c) {
        if (c.isIpHost() || c.domain().isEmpty()) {
            return List.of();
        }
        if (HomoglyphUtil.containsPunycodeLabel(c.host()) || c.host().chars().anyMatch(ch -> ch > 127)) {
            return List.of(); // already covered by detectHomograph
        }

        String domain = c.domain().toLowerCase(Locale.ROOT);
        int maxDistance = config.scoring().typosquattingMaxDistance();

        String bestBrand = null;
        int bestDistance = Integer.MAX_VALUE;
        for (String brand : config.brands()) {
            String normalizedBrand = brand.toLowerCase(Locale.ROOT);
            if (domain.equals(normalizedBrand)) {
                return List.of(); // exact match to a known brand: not typosquatting
            }
            int distance = LevenshteinDistance.distance(domain, normalizedBrand);
            if (distance < bestDistance) {
                bestDistance = distance;
                bestBrand = normalizedBrand;
            }
        }
        if (bestBrand != null && bestDistance <= maxDistance) {
            return List.of(new Signal("typosquatting", SignalCategory.URL,
                    "Domain closely resembles brand '" + bestBrand + "' (edit distance " + bestDistance + ")",
                    c.registrableDomain()));
        }

        // Combosquatting: brand name embedded in a longer domain, e.g. "paypal-secure-login".
        for (String brand : config.brands()) {
            String normalizedBrand = brand.toLowerCase(Locale.ROOT);
            if (domain.length() > normalizedBrand.length() && domain.contains(normalizedBrand)) {
                return List.of(new Signal("typosquatting", SignalCategory.URL,
                        "Domain embeds brand name '" + normalizedBrand + "' alongside other text",
                        c.registrableDomain()));
            }
        }

        // Combosquatting combined with a typo, e.g. "micros0ft-support.com": the brand
        // segment alone (split on the common "-"/"_" separators) is a close edit-distance
        // match even though the full domain isn't, and the substitution breaks plain
        // substring containment.
        for (String token : domain.split("[-_]")) {
            if (token.isEmpty()) {
                continue;
            }
            for (String brand : config.brands()) {
                String normalizedBrand = brand.toLowerCase(Locale.ROOT);
                if (token.equals(normalizedBrand)) {
                    continue; // exact segment match is handled by the substring check above
                }
                int distance = LevenshteinDistance.distance(token, normalizedBrand);
                if (distance > 0 && distance <= maxDistance) {
                    return List.of(new Signal("typosquatting", SignalCategory.URL,
                            "Domain segment '" + token + "' closely resembles brand '" + normalizedBrand
                                    + "' (edit distance " + distance + ")",
                            c.registrableDomain()));
                }
            }
        }

        // Brand impersonation via subdomain, e.g. "paypal.secure-login.com".
        if (!c.subdomain().isEmpty()) {
            for (String label : c.subdomain().split("\\.")) {
                for (String brand : config.brands()) {
                    if (label.equalsIgnoreCase(brand) && !domain.equals(brand.toLowerCase(Locale.ROOT))) {
                        return List.of(new Signal("typosquatting", SignalCategory.URL,
                                "Brand name '" + brand + "' used as a subdomain of an unrelated domain",
                                c.host()));
                    }
                }
            }
        }

        return List.of();
    }

    private List<Signal> detectLongOrObfuscatedUrl(UrlComponents c) {
        List<Signal> signals = new ArrayList<>();
        var scoring = config.scoring();

        if (c.rawUrl().length() > scoring.longUrlThreshold()) {
            signals.add(new Signal("longOrObfuscatedUrl", SignalCategory.URL,
                    "URL is abnormally long (" + c.rawUrl().length() + " characters)", c.rawUrl()));
        }

        int paramCount = c.queryParams().values().stream().mapToInt(List::size).sum();
        if (paramCount > scoring.maxQueryParams()) {
            signals.add(new Signal("excessiveQueryParams", SignalCategory.URL,
                    "URL has an excessive number of query parameters (" + paramCount + ")", null));
        }

        Matcher percentMatcher = PERCENT_ENCODED_PATTERN.matcher(c.rawUrl());
        int encodedCount = 0;
        while (percentMatcher.find()) {
            encodedCount++;
        }
        if (encodedCount >= scoring.encodedCharThreshold()) {
            signals.add(new Signal("encodedCharacters", SignalCategory.URL,
                    "URL contains many percent-encoded characters (" + encodedCount + "), often used to obfuscate content",
                    null));
        }

        if (containsNestedRedirect(c)) {
            signals.add(new Signal("nestedRedirect", SignalCategory.URL,
                    "URL appears to embed another URL in its query string, a common open-redirect phishing pattern",
                    null));
        }

        return signals;
    }

    private static boolean containsNestedRedirect(UrlComponents c) {
        for (List<String> values : c.queryParams().values()) {
            for (String value : values) {
                if (EMBEDDED_URL_PATTERN.matcher(value).find()) {
                    return true;
                }
            }
        }
        return EMBEDDED_URL_PATTERN.matcher(c.path() == null ? "" : c.path()).find();
    }
}
