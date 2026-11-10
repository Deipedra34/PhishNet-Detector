package com.phishnet.feeds;

import java.util.Locale;
import java.util.Optional;

/**
 * Turns URLs - from a feed or from a scan - into comparable lookup keys, so
 * {@code HTTP://WWW.Evil.example:80/login/} and {@code https://evil.example/login}
 * land on the same entry.
 *
 * A key is {@code host[:port]path[?query]}:
 * <ul>
 *   <li>the scheme is dropped, so http and https versions of a page match (feeds
 *       list whichever one was reported; the phishing page is the same)</li>
 *   <li>the host is lowercased, without a trailing dot, user info, or a leading
 *       {@code www.}</li>
 *   <li>a default port (80, 443) is dropped</li>
 *   <li>the fragment is dropped; a missing path becomes {@code /}, and one
 *       trailing slash is removed from a longer path</li>
 *   <li>path and query keep their case: servers can treat them case-sensitively</li>
 * </ul>
 *
 * Deliberately a hand-rolled parse rather than {@link java.net.URI}: feed
 * entries regularly contain spaces and other characters URI rejects, and a
 * lenient parse keeps those entries matchable instead of dropping them.
 */
public final class FeedUrls {

    private FeedUrls() {
    }

    /** The lookup key for {@code raw}, or empty if it has no usable host. */
    public static Optional<String> normalize(String raw) {
        Parts parts = parse(raw);
        if (parts == null) {
            return Optional.empty();
        }
        return Optional.of(parts.host + parts.port + parts.pathAndQuery);
    }

    /** Just the normalized host of {@code raw} (no port), or empty if it has none. */
    public static Optional<String> host(String raw) {
        Parts parts = parse(raw);
        return parts == null ? Optional.empty() : Optional.of(parts.host);
    }

    /** The host part of a key produced by {@link #normalize(String)}. */
    public static String hostOfKey(String key) {
        int end = key.length();
        for (int i = 0; i < key.length(); i++) {
            char c = key.charAt(i);
            if (c == '/' || c == '?') {
                end = i;
                break;
            }
        }
        String hostAndPort = key.substring(0, end);
        if (hostAndPort.startsWith("[")) {
            int close = hostAndPort.indexOf(']');
            return close > 0 ? hostAndPort.substring(0, close + 1) : hostAndPort;
        }
        int colon = hostAndPort.lastIndexOf(':');
        return colon > 0 ? hostAndPort.substring(0, colon) : hostAndPort;
    }

    private record Parts(String host, String port, String pathAndQuery) {
    }

    private static Parts parse(String raw) {
        if (raw == null) {
            return null;
        }
        String s = raw.strip();
        if (s.isEmpty()) {
            return null;
        }

        String scheme = "http";
        int schemeEnd = s.indexOf("://");
        if (schemeEnd > 0 && s.substring(0, schemeEnd).chars().allMatch(FeedUrls::isSchemeChar)) {
            scheme = s.substring(0, schemeEnd).toLowerCase(Locale.ROOT);
            s = s.substring(schemeEnd + 3);
        }

        int authorityEnd = s.length();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '/' || c == '?' || c == '#') {
                authorityEnd = i;
                break;
            }
        }
        String authority = s.substring(0, authorityEnd);
        String rest = s.substring(authorityEnd);

        int at = authority.lastIndexOf('@');
        if (at >= 0) {
            authority = authority.substring(at + 1);
        }

        String host;
        String port = "";
        if (authority.startsWith("[")) {
            int close = authority.indexOf(']');
            if (close < 0) {
                return null;
            }
            host = authority.substring(0, close + 1);
            if (authority.length() > close + 2 && authority.charAt(close + 1) == ':') {
                port = authority.substring(close + 2);
            }
        } else {
            int colon = authority.lastIndexOf(':');
            if (colon >= 0) {
                host = authority.substring(0, colon);
                port = authority.substring(colon + 1);
            } else {
                host = authority;
            }
        }

        host = host.toLowerCase(Locale.ROOT);
        while (host.endsWith(".")) {
            host = host.substring(0, host.length() - 1);
        }
        if (host.startsWith("www.")) {
            host = host.substring(4);
        }
        if (host.isEmpty() || host.chars().anyMatch(Character::isWhitespace)) {
            return null;
        }

        if (port.isEmpty() || (scheme.equals("http") && port.equals("80")) || (scheme.equals("https") && port.equals("443"))) {
            port = "";
        } else {
            port = ":" + port;
        }

        int fragment = rest.indexOf('#');
        if (fragment >= 0) {
            rest = rest.substring(0, fragment);
        }
        int queryStart = rest.indexOf('?');
        String path = queryStart >= 0 ? rest.substring(0, queryStart) : rest;
        String query = queryStart >= 0 ? rest.substring(queryStart) : "";
        if (path.isEmpty()) {
            path = "/";
        } else if (path.length() > 1 && path.endsWith("/")) {
            path = path.substring(0, path.length() - 1);
        }
        if (query.equals("?")) {
            query = "";
        }
        return new Parts(host, port, path + query);
    }

    private static boolean isSchemeChar(int c) {
        return Character.isLetterOrDigit(c) || c == '+' || c == '-' || c == '.';
    }
}
