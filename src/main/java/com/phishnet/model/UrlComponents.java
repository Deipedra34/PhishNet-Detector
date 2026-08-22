package com.phishnet.model;

import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * Parsed pieces of a URL, produced by {@code UrlAnalyzer}.
 *
 * Domain splitting is just a heuristic: last label is the TLD, the one
 * before it is the registrable domain, unless the host ends in a known
 * two-part suffix like co.uk. Good enough for phishing checks without
 * pulling in a full public-suffix-list.
 */
public final class UrlComponents {

    private final String rawUrl;
    private final String scheme;
    private final String host;
    private final int port;
    private final String subdomain;
    private final String domain;
    private final String tld;
    private final String path;
    private final String fragment;
    private final Map<String, List<String>> queryParams;
    private final boolean ipHost;

    public UrlComponents(String rawUrl, String scheme, String host, int port,
                          String subdomain, String domain, String tld,
                          String path, String fragment,
                          Map<String, List<String>> queryParams, boolean ipHost) {
        this.rawUrl = rawUrl;
        this.scheme = scheme;
        this.host = host;
        this.port = port;
        this.subdomain = subdomain;
        this.domain = domain;
        this.tld = tld;
        this.path = path;
        this.fragment = fragment;
        this.queryParams = Collections.unmodifiableMap(queryParams);
        this.ipHost = ipHost;
    }

    public String rawUrl() {
        return rawUrl;
    }

    public String scheme() {
        return scheme;
    }

    public String host() {
        return host;
    }

    public int port() {
        return port;
    }

    public String subdomain() {
        return subdomain;
    }

    /** Registrable domain name without the TLD, e.g. {@code "paypal"} for {@code login.paypal.com}. */
    public String domain() {
        return domain;
    }

    public String tld() {
        return tld;
    }

    public String path() {
        return path;
    }

    public String fragment() {
        return fragment;
    }

    public Map<String, List<String>> queryParams() {
        return queryParams;
    }

    public boolean isIpHost() {
        return ipHost;
    }

    /** Registrable domain plus TLD, e.g. {@code "paypal.com"}. */
    public String registrableDomain() {
        if (domain.isEmpty()) {
            return tld;
        }
        return tld.isEmpty() ? domain : domain + "." + tld;
    }
}
