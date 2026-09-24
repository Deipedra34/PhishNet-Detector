package com.phishnet.analyzer;

import com.phishnet.model.DomainAgeResult;
import com.phishnet.model.UrlComponents;

import java.io.IOException;
import java.net.IDN;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.time.Clock;
import java.time.DateTimeException;
import java.time.LocalDate;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Looks up when a domain was registered, via plain-text WHOIS (RFC 3912).
 *
 * The registry's WHOIS server is picked from a small built-in table for the
 * most common TLDs, or else asked of whois.iana.org (its {@code refer:} line).
 * If the registry's reply has no creation date but names a registrar WHOIS
 * server (thin registries), that server is asked once too.
 *
 * check() never throws: any network error, timeout, or unparseable reply
 * comes back as {@link DomainAgeResult.Status#UNKNOWN} with a reason, so a
 * scan always completes. The whole lookup - IANA referral, registry, and
 * registrar together - shares one time budget (5 seconds by default).
 *
 * Within one run, results are cached per domain and IANA referrals per TLD,
 * and a server that failed once is not retried - so a batch full of URLs on
 * an unreachable registry costs one timeout, not one per URL.
 *
 * The parsing (parseCreationDate, parseReferral) is static and network-free,
 * so it's tested directly against canned WHOIS responses.
 */
public final class DomainAgeChecker {

    public static final int DEFAULT_TIMEOUT_MILLIS = 5000;

    static final String IANA_SERVER = "whois.iana.org";

    /** Registry servers for the busiest TLDs, so they skip the IANA round-trip. */
    private static final Map<String, String> KNOWN_REGISTRY_SERVERS = Map.of(
            "com", "whois.verisign-grs.com",
            "net", "whois.verisign-grs.com",
            "org", "whois.pir.org",
            "uk", "whois.nic.uk");

    /**
     * Line labels that carry a domain's creation date, across registry formats:
     * "Creation Date:" (ICANN gTLDs), "created:" (RIPE-style ccTLDs, e.g. .fr/.se/.ru),
     * "Registered on:" (Nominet .uk), "Registration Time:" (CNNIC .cn),
     * "Created on....:" (.tr), "Domain Registration Date:", "Record created on", etc.
     * Dotted leaders before the colon are tolerated.
     */
    private static final Pattern CREATION_LINE = Pattern.compile(
            "^[ \\t]*(?:creation[ _]date|created(?:[ _]on)?|registered(?:[ _](?:on|date))?"
                    + "|registration[ _](?:date|time)|domain[ _](?:registration[ _]date|created|create[ _]date)"
                    + "|record[ _]created(?:[ _]on)?)[ \\t.]*:[ \\t]*(\\S.*?)[ \\t]*$",
            Pattern.CASE_INSENSITIVE | Pattern.MULTILINE);

    /** JPRS (.jp) uses bracketed labels with no colon: "[Created on]  2001/01/01" / "[登録年月日]". */
    private static final Pattern JP_CREATION_LINE = Pattern.compile(
            "^[ \\t]*\\[(?:Created on|登録年月日)\\][ \\t]*(\\S.*?)[ \\t]*$",
            Pattern.CASE_INSENSITIVE | Pattern.MULTILINE);

    private static final Pattern IANA_REFER = Pattern.compile(
            "^[ \\t]*(?:refer|whois):[ \\t]*(\\S+)", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE);
    private static final Pattern REGISTRAR_REFER = Pattern.compile(
            "^[ \\t]*(?:Registrar WHOIS Server|ReferralServer):[ \\t]*(\\S+)",
            Pattern.CASE_INSENSITIVE | Pattern.MULTILINE);

    private static final Pattern NOT_FOUND = Pattern.compile(
            "no match|not found|no data found|no entries found|no object found|status:\\s*(?:free|available)"
                    + "|domain not registered",
            Pattern.CASE_INSENSITIVE);

    /** A date layout: regex plus which capture group holds the year, month, and day (0 = no day, use the 1st). */
    private record DateShape(Pattern pattern, int yearGroup, int monthGroup, int dayGroup) {
    }

    /** Tried in order against the text after a creation label; first valid date wins. */
    private static final List<DateShape> DATE_SHAPES = List.of(
            // 1997-09-15T04:00:00Z, 2003-03-17 12:20:05, 2004.06.11, 2001/01/01
            new DateShape(Pattern.compile("(\\d{4})[-./](\\d{1,2})[-./](\\d{1,2})"), 1, 2, 3),
            // 15-Mar-2002, 15 March 2002
            new DateShape(Pattern.compile("(\\d{1,2})[-. /]([A-Za-z]{3,9})[-. /,]+(\\d{4})"), 3, 2, 1),
            // 2000-Jan-01
            new DateShape(Pattern.compile("(\\d{4})[-. /]([A-Za-z]{3,9})[-. /]+(\\d{1,2})"), 1, 2, 3),
            // March 15, 2002
            new DateShape(Pattern.compile("([A-Za-z]{3,9})[ ]+(\\d{1,2}),?[ ]+(\\d{4})"), 3, 1, 2),
            // 15.03.2002, 15-03-2002 (day first, as European registries write it)
            new DateShape(Pattern.compile("(\\d{1,2})[-.](\\d{1,2})[-.](\\d{4})"), 3, 2, 1),
            // 20020315
            new DateShape(Pattern.compile("\\b(\\d{4})(\\d{2})(\\d{2})\\b"), 1, 2, 3),
            // Month and year only - Nominet's legacy "before Aug-1996". Taken as the 1st of that
            // month, which can only understate the age, never make an old domain look new.
            new DateShape(Pattern.compile("\\b([A-Za-z]{3,9})[-. ](\\d{4})\\b"), 2, 1, 0));

    private static final Pattern VALID_DOMAIN = Pattern.compile("^[a-z0-9-]+(\\.[a-z0-9-]+)+$");

    private static final List<String> MONTHS = List.of(
            "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec");

    /** The first .com was registered in 1985; anything earlier is a parse mistake. */
    private static final LocalDate EARLIEST_PLAUSIBLE = LocalDate.of(1985, 1, 1);

    private final WhoisClient client;
    private final int timeoutMillis;
    private final Clock clock;

    private final Map<String, DomainAgeResult> resultCache = new HashMap<>();
    private final Map<String, Optional<String>> registryServerCache = new HashMap<>();
    private final Set<String> failedServers = new HashSet<>();

    public DomainAgeChecker() {
        this(new SocketWhoisClient(), DEFAULT_TIMEOUT_MILLIS, Clock.systemDefaultZone());
    }

    public DomainAgeChecker(WhoisClient client) {
        this(client, DEFAULT_TIMEOUT_MILLIS, Clock.systemDefaultZone());
    }

    public DomainAgeChecker(WhoisClient client, int timeoutMillis, Clock clock) {
        this.client = client;
        this.timeoutMillis = timeoutMillis;
        this.clock = clock;
    }

    /**
     * Looks up the registrable domain of an already-parsed URL. IP hosts and
     * URLs with no host have no domain to look up and come back SKIPPED.
     */
    public DomainAgeResult check(UrlComponents components) {
        if (components == null || components.host().isEmpty() || components.isIpHost()
                || components.domain().isEmpty() || components.tld().isEmpty()) {
            return DomainAgeResult.skipped();
        }
        return check(components.registrableDomain());
    }

    /** Looks up a registrable domain name such as {@code "example.com"}. Never throws. */
    public DomainAgeResult check(String domainName) {
        String domain;
        try {
            domain = normalize(domainName);
        } catch (IllegalArgumentException e) {
            return DomainAgeResult.unknown(domainName, "not a valid domain name for WHOIS");
        }
        if (!VALID_DOMAIN.matcher(domain).matches()) {
            // Also keeps CR/LF or other junk from ever reaching a WHOIS server as part of the query.
            return DomainAgeResult.unknown(domainName, "not a valid domain name for WHOIS");
        }
        DomainAgeResult cached = resultCache.get(domain);
        if (cached == null) {
            cached = lookup(domain);
            resultCache.put(domain, cached);
        }
        return cached;
    }

    private DomainAgeResult lookup(String domain) {
        long deadline = System.nanoTime() + timeoutMillis * 1_000_000L;
        String tld = domain.substring(domain.lastIndexOf('.') + 1);
        try {
            Optional<String> registry = registryServerFor(tld, deadline);
            if (registry.isEmpty()) {
                return DomainAgeResult.unknown(domain, "no WHOIS server known for ." + tld);
            }
            LocalDate today = LocalDate.now(clock);
            String server = registry.get();
            String response = query(server, domain, deadline);
            Optional<LocalDate> created = parseCreationDate(response, today);

            if (created.isEmpty()) {
                Optional<String> registrar = parseReferral(response, REGISTRAR_REFER);
                if (registrar.isPresent() && !registrar.get().equalsIgnoreCase(server)) {
                    String registrarResponse = query(registrar.get(), domain, deadline);
                    created = parseCreationDate(registrarResponse, today);
                    if (created.isPresent()) {
                        server = registrar.get();
                    }
                }
            }

            if (created.isEmpty()) {
                return DomainAgeResult.unknown(domain, NOT_FOUND.matcher(response).find()
                        ? "domain not found in WHOIS"
                        : "no creation date in WHOIS response");
            }
            long ageDays = ChronoUnit.DAYS.between(created.get(), today);
            return DomainAgeResult.known(domain, created.get(), ageDays, server);
        } catch (SocketTimeoutException e) {
            return DomainAgeResult.unknown(domain, "WHOIS lookup timed out");
        } catch (UnknownHostException e) {
            return DomainAgeResult.unknown(domain, "WHOIS server unreachable: " + e.getMessage());
        } catch (IOException e) {
            return DomainAgeResult.unknown(domain, "WHOIS lookup failed: " + e.getMessage());
        } catch (RuntimeException e) {
            // A buggy client or a bizarre reply must never take the whole scan down.
            return DomainAgeResult.unknown(domain, "WHOIS lookup failed: " + e);
        }
    }

    private Optional<String> registryServerFor(String tld, long deadline) throws IOException {
        String known = KNOWN_REGISTRY_SERVERS.get(tld);
        if (known != null) {
            return Optional.of(known);
        }
        Optional<String> cached = registryServerCache.get(tld);
        if (cached != null) {
            return cached;
        }
        Optional<String> referred = parseReferral(query(IANA_SERVER, tld, deadline), IANA_REFER);
        registryServerCache.put(tld, referred);
        return referred;
    }

    private String query(String server, String query, long deadline) throws IOException {
        if (failedServers.contains(server)) {
            throw new IOException(server + " already failed earlier in this run");
        }
        long remaining = (deadline - System.nanoTime()) / 1_000_000L;
        if (remaining <= 0) {
            throw new SocketTimeoutException("lookup time budget used up before querying " + server);
        }
        try {
            String response = client.query(server, query, (int) remaining);
            return response == null ? "" : response;
        } catch (IOException e) {
            failedServers.add(server);
            throw e;
        }
    }

    // --- parsing (static, network-free) -------------------------------------

    static String normalize(String domainName) {
        String d = domainName == null ? "" : domainName.trim().toLowerCase(Locale.ROOT);
        while (d.endsWith(".")) {
            d = d.substring(0, d.length() - 1);
        }
        return d.isEmpty() ? d : IDN.toASCII(d).toLowerCase(Locale.ROOT);
    }

    /**
     * Finds the first creation-date line in a WHOIS reply whose value parses
     * to a plausible date (not before 1985, not after tomorrow).
     */
    public static Optional<LocalDate> parseCreationDate(String response, LocalDate today) {
        if (response == null || response.isEmpty()) {
            return Optional.empty();
        }
        for (Pattern linePattern : List.of(CREATION_LINE, JP_CREATION_LINE)) {
            Matcher m = linePattern.matcher(response);
            while (m.find()) {
                Optional<LocalDate> date = parseDate(m.group(1));
                // Allow "tomorrow" so a registry in a timezone ahead of ours doesn't get rejected.
                if (date.isPresent() && !date.get().isBefore(EARLIEST_PLAUSIBLE)
                        && !date.get().isAfter(today.plusDays(1))) {
                    return date;
                }
            }
        }
        return Optional.empty();
    }

    /** Parses one date value in any of the formats registries commonly use. */
    static Optional<LocalDate> parseDate(String value) {
        if (value == null) {
            return Optional.empty();
        }
        String v = value.trim();
        for (DateShape shape : DATE_SHAPES) {
            Matcher m = shape.pattern().matcher(v);
            while (m.find()) {
                Optional<LocalDate> date = date(m.group(shape.yearGroup()), m.group(shape.monthGroup()),
                        shape.dayGroup() == 0 ? "1" : m.group(shape.dayGroup()));
                if (date.isPresent()) {
                    return date;
                }
            }
        }
        return Optional.empty();
    }

    /** Month as a number ("3") or a name/abbreviation ("Mar", "March"); -1 if it's neither. */
    private static int month(String text) {
        if (!text.isEmpty() && Character.isDigit(text.charAt(0))) {
            return Integer.parseInt(text);
        }
        if (text.length() < 3) {
            return -1;
        }
        int index = MONTHS.indexOf(text.substring(0, 3).toLowerCase(Locale.ROOT));
        return index < 0 ? -1 : index + 1;
    }

    private static Optional<LocalDate> date(String year, String month, String day) {
        try {
            return Optional.of(LocalDate.of(Integer.parseInt(year), month(month), Integer.parseInt(day)));
        } catch (DateTimeException | NumberFormatException e) {
            return Optional.empty();
        }
    }

    /** IANA {@code refer:} line: the registry WHOIS server for a TLD. */
    public static Optional<String> parseIanaReferral(String response) {
        return parseReferral(response, IANA_REFER);
    }

    /** {@code Registrar WHOIS Server:} line in a thin registry's reply. */
    public static Optional<String> parseRegistrarReferral(String response) {
        return parseReferral(response, REGISTRAR_REFER);
    }

    private static Optional<String> parseReferral(String response, Pattern pattern) {
        if (response == null) {
            return Optional.empty();
        }
        Matcher m = pattern.matcher(response);
        while (m.find()) {
            String server = m.group(1).toLowerCase(Locale.ROOT)
                    .replaceFirst("^(?:whois|rwhois|https?)://", "")
                    .replaceFirst("[:/].*$", "");
            // Registrars sometimes put a web URL here instead of a WHOIS host; only accept a bare hostname.
            if (VALID_DOMAIN.matcher(server).matches()) {
                return Optional.of(server);
            }
        }
        return Optional.empty();
    }
}
