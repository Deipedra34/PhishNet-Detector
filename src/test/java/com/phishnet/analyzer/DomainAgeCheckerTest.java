package com.phishnet.analyzer;

import com.phishnet.model.DomainAgeResult;
import com.phishnet.util.ConfigLoader;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.time.Clock;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for DomainAgeChecker. Every test here runs against canned WHOIS
 * text or a fake {@link WhoisClient} - none of them open a socket. The one
 * real-network smoke test lives separately in DomainAgeCheckerNetworkTest.
 */
class DomainAgeCheckerTest {

    private static final LocalDate TODAY = LocalDate.of(2026, 9, 24);
    private static final Clock FIXED_CLOCK = Clock.fixed(Instant.parse("2026-09-24T12:00:00Z"), ZoneOffset.UTC);

    /** Fake WHOIS network: canned reply per server, every query recorded. */
    private static final class FakeWhois implements WhoisClient {
        final Map<String, String> replies;
        final List<String> calls = new ArrayList<>();
        final List<Integer> timeouts = new ArrayList<>();

        FakeWhois(Map<String, String> replies) {
            this.replies = replies;
        }

        @Override
        public String query(String server, String query, int timeoutMillis) throws IOException {
            calls.add(server + " " + query);
            timeouts.add(timeoutMillis);
            String reply = replies.get(server);
            if (reply == null) {
                throw new UnknownHostException(server);
            }
            return reply;
        }
    }

    private static DomainAgeChecker checker(WhoisClient client) {
        return new DomainAgeChecker(client, 5000, FIXED_CLOCK);
    }

    private static Optional<LocalDate> parse(String response) {
        return DomainAgeChecker.parseCreationDate(response, TODAY);
    }

    // --- parsing: registry formats -------------------------------------------

    @Test
    void parsesIcannCreationDateFormat() {
        String verisign = "   Domain Name: EXAMPLE.COM\r\n"
                + "   Registry Domain ID: 2336799_DOMAIN_COM-VRSN\r\n"
                + "   Updated Date: 2024-08-14T07:01:34Z\r\n"
                + "   Creation Date: 1995-08-14T04:00:00Z\r\n"
                + "   Registry Expiry Date: 2025-08-13T04:00:00Z\r\n";
        assertEquals(Optional.of(LocalDate.of(1995, 8, 14)), parse(verisign));
    }

    @Test
    void parsesRipeStyleCreatedFormat() {
        String afnic = "domain:      example.fr\nstatus:      ACTIVE\ncreated:     2004-06-11T10:12:43Z\n";
        assertEquals(Optional.of(LocalDate.of(2004, 6, 11)), parse(afnic));
    }

    @Test
    void parsesDottedCreatedFormat() {
        String ru = "domain:        EXAMPLE.RU\ncreated:       1997.03.18\npaid-till:     2027.03.31\n";
        assertEquals(Optional.of(LocalDate.of(1997, 3, 18)), parse(ru));
    }

    @Test
    void parsesNominetRegisteredOnFormat() {
        String nominet = "    Domain name:\n        example.co.uk\n\n    Relevant dates:\n"
                + "        Registered on: 15-Mar-2002\n        Expiry date:  15-Mar-2027\n";
        assertEquals(Optional.of(LocalDate.of(2002, 3, 15)), parse(nominet));
    }

    @Test
    void parsesNominetLegacyBeforeMonthYearFormat() {
        String nominet = "    Relevant dates:\n        Registered on: before Aug-1996\n"
                + "        Expiry date:  13-Dec-2034\n";
        assertEquals(Optional.of(LocalDate.of(1996, 8, 1)), parse(nominet));
    }

    @Test
    void parsesCnnicRegistrationTimeFormat() {
        String cnnic = "Domain Name: example.cn\nRegistration Time: 2003-03-17 12:20:05\n"
                + "Expiration Time: 2027-03-17 12:48:36\n";
        assertEquals(Optional.of(LocalDate.of(2003, 3, 17)), parse(cnnic));
    }

    @Test
    void parsesTrDottedLeaderFormatWithNamedMonth() {
        String tr = "** Additional Info:\nCreated on..............: 2000-Jan-01.\nExpires on..............: 2027-Jan-01.\n";
        assertEquals(Optional.of(LocalDate.of(2000, 1, 1)), parse(tr));
    }

    @Test
    void parsesJprsBracketedFormat() {
        String jp = "[Domain Name]                   EXAMPLE.JP\n[Created on]                    2001/02/03\n";
        assertEquals(Optional.of(LocalDate.of(2001, 2, 3)), parse(jp));
    }

    @Test
    void parsesDayFirstNumericAndCompactDates() {
        assertEquals(Optional.of(LocalDate.of(2010, 4, 5)), parse("Registration Date: 05.04.2010\n"));
        assertEquals(Optional.of(LocalDate.of(1999, 12, 31)), parse("created: 19991231 #12345\n"));
        assertEquals(Optional.of(LocalDate.of(2002, 3, 15)), parse("Domain Registration Date: March 15, 2002\n"));
    }

    @Test
    void labelMatchingIsCaseInsensitive() {
        assertEquals(Optional.of(LocalDate.of(2020, 1, 2)), parse("CREATION DATE: 2020-01-02\n"));
    }

    @Test
    void doesNotConfuseExpiryOrUpdatedDatesWithCreation() {
        String noCreation = "Updated Date: 2024-01-01T00:00:00Z\n"
                + "Registrar Registration Expiration Date: 2027-01-01T00:00:00Z\n"
                + "Registry Expiry Date: 2027-01-01T00:00:00Z\n";
        assertEquals(Optional.empty(), parse(noCreation));
    }

    // --- parsing: malformed / implausible -------------------------------------

    @Test
    void emptyOrNullResponseHasNoDate() {
        assertEquals(Optional.empty(), parse(null));
        assertEquals(Optional.empty(), parse(""));
        assertEquals(Optional.empty(), parse("   \r\n\r\n"));
    }

    @Test
    void garbageResponseHasNoDate() {
        assertEquals(Optional.empty(), parse("\u0000\u0001 %%%% <html>502 Bad Gateway</html> ::::"));
        assertEquals(Optional.empty(), parse("Creation Date: not-a-date\n"));
        assertEquals(Optional.empty(), parse("Creation Date:\n"));
    }

    @Test
    void rejectsImpossibleCalendarDates() {
        assertEquals(Optional.empty(), parse("Creation Date: 2021-02-30T00:00:00Z\n"));
        assertEquals(Optional.empty(), parse("Creation Date: 2021-13-01\n"));
    }

    @Test
    void rejectsFutureAndPre1985Dates() {
        assertEquals(Optional.empty(), parse("Creation Date: 2030-01-01\n"));
        assertEquals(Optional.empty(), parse("Creation Date: 1970-01-01\n"));
        // one day ahead is tolerated (registry clock/timezone ahead of ours)
        assertEquals(Optional.of(TODAY.plusDays(1)), parse("Creation Date: " + TODAY.plusDays(1) + "\n"));
    }

    @Test
    void skipsUnparseableLabelAndUsesNextPlausibleOne() {
        String response = "Registered: yes\nCreation Date: 2012-05-06\n";
        assertEquals(Optional.of(LocalDate.of(2012, 5, 6)), parse(response));
    }

    @Test
    void rateLimitReplyHasNoDate() {
        assertEquals(Optional.empty(), parse("%% Query rate limit exceeded. Try again later.\n"));
    }

    // --- parsing: referrals ---------------------------------------------------

    @Test
    void parsesIanaReferral() {
        String iana = "% IANA WHOIS server\n\ndomain:       IO\n\norganisation: Internet Computer Bureau Limited\n"
                + "refer:        whois.nic.io\n";
        assertEquals(Optional.of("whois.nic.io"), DomainAgeChecker.parseIanaReferral(iana));
    }

    @Test
    void parsesRegistrarReferralAndIgnoresWebUrls() {
        assertEquals(Optional.of("whois.markmonitor.com"),
                DomainAgeChecker.parseRegistrarReferral("Registrar WHOIS Server: whois.markmonitor.com\n"));
        assertEquals(Optional.of("whois.example-registrar.net"),
                DomainAgeChecker.parseRegistrarReferral("Registrar WHOIS Server: whois://whois.example-registrar.net\n"));
        assertEquals(Optional.empty(),
                DomainAgeChecker.parseRegistrarReferral("Registrar WHOIS Server: \n"));
        assertEquals(Optional.empty(), DomainAgeChecker.parseIanaReferral(null));
    }

    // --- lookup flow (fake client) --------------------------------------------

    @Test
    void knownTldGoesStraightToRegistryAndComputesAge() {
        FakeWhois whois = new FakeWhois(Map.of("whois.verisign-grs.com", "Creation Date: 2026-09-14T00:00:00Z\n"));

        DomainAgeResult result = checker(whois).check("Fresh-Site.COM");

        assertTrue(result.isKnown());
        assertEquals("fresh-site.com", result.domain());
        assertEquals(LocalDate.of(2026, 9, 14), result.creationDate());
        assertEquals(10, result.ageDays());
        assertEquals("whois.verisign-grs.com", result.whoisServer());
        assertEquals(List.of("whois.verisign-grs.com fresh-site.com"), whois.calls);
    }

    @Test
    void unknownTldIsResolvedThroughIanaAndCachedPerTld() {
        FakeWhois whois = new FakeWhois(Map.of(
                "whois.iana.org", "domain: IO\nrefer: whois.nic.io\n",
                "whois.nic.io", "Creation Date: 2020-01-01T00:00:00Z\n"));
        DomainAgeChecker checker = checker(whois);

        assertTrue(checker.check("one.io").isKnown());
        assertTrue(checker.check("two.io").isKnown());

        assertEquals(List.of("whois.iana.org io", "whois.nic.io one.io", "whois.nic.io two.io"), whois.calls);
    }

    @Test
    void thinRegistryReplyFollowsRegistrarReferral() {
        FakeWhois whois = new FakeWhois(Map.of(
                "whois.verisign-grs.com", "Domain Name: THIN.COM\nRegistrar WHOIS Server: whois.registrar.test\n",
                "whois.registrar.test", "Creation Date: 2015-03-04T00:00:00Z\n"));

        DomainAgeResult result = checker(whois).check("thin.com");

        assertTrue(result.isKnown());
        assertEquals(LocalDate.of(2015, 3, 4), result.creationDate());
        assertEquals("whois.registrar.test", result.whoisServer());
    }

    @Test
    void repeatedDomainIsOnlyLookedUpOnce() {
        FakeWhois whois = new FakeWhois(Map.of("whois.verisign-grs.com", "Creation Date: 2020-01-01\n"));
        DomainAgeChecker checker = checker(whois);

        checker.check("example.com");
        checker.check("EXAMPLE.com.");

        assertEquals(1, whois.calls.size());
    }

    @Test
    void timeoutReturnsUnknownInsteadOfThrowing() {
        WhoisClient slow = (server, query, timeoutMillis) -> {
            throw new SocketTimeoutException("Read timed out");
        };

        DomainAgeResult result = checker(slow).check("example.com");

        assertEquals(DomainAgeResult.Status.UNKNOWN, result.status());
        assertEquals("WHOIS lookup timed out", result.reason());
        assertEquals("unknown", result.formatAge());
    }

    @Test
    void unreachableServerReturnsUnknown() {
        DomainAgeResult result = checker(new FakeWhois(Map.of())).check("example.com");

        assertEquals(DomainAgeResult.Status.UNKNOWN, result.status());
        assertTrue(result.reason().startsWith("WHOIS server unreachable"), result.reason());
    }

    @Test
    void unexpectedRuntimeExceptionFromClientReturnsUnknown() {
        WhoisClient broken = (server, query, timeoutMillis) -> {
            throw new IllegalStateException("boom");
        };

        DomainAgeResult result = checker(broken).check("example.com");

        assertEquals(DomainAgeResult.Status.UNKNOWN, result.status());
        assertTrue(result.reason().contains("boom"));
    }

    @Test
    void failedServerIsNotRetriedForLaterDomainsInTheSameRun() {
        List<String> calls = new ArrayList<>();
        WhoisClient dead = (server, query, timeoutMillis) -> {
            calls.add(query);
            throw new SocketTimeoutException("connect timed out");
        };
        DomainAgeChecker checker = checker(dead);

        checker.check("a.com");
        DomainAgeResult second = checker.check("b.com");

        assertEquals(List.of("a.com"), calls);
        assertEquals(DomainAgeResult.Status.UNKNOWN, second.status());
    }

    @Test
    void notFoundReplyReturnsUnknownWithReason() {
        FakeWhois whois = new FakeWhois(Map.of("whois.verisign-grs.com", "No match for \"NOPE-XYZ.COM\".\r\n"));

        DomainAgeResult result = checker(whois).check("nope-xyz.com");

        assertEquals(DomainAgeResult.Status.UNKNOWN, result.status());
        assertEquals("domain not found in WHOIS", result.reason());
    }

    @Test
    void replyWithoutCreationDateReturnsUnknown() {
        FakeWhois whois = new FakeWhois(Map.of("whois.pir.org", "Domain Name: example.org\nStatus: ok\n"));

        DomainAgeResult result = checker(whois).check("example.org");

        assertEquals(DomainAgeResult.Status.UNKNOWN, result.status());
        assertEquals("no creation date in WHOIS response", result.reason());
    }

    @Test
    void nullReplyIsTreatedAsEmpty() {
        DomainAgeResult result = checker((server, query, timeoutMillis) -> null).check("example.com");
        assertEquals(DomainAgeResult.Status.UNKNOWN, result.status());
    }

    @Test
    void tldWithNoIanaReferralReturnsUnknown() {
        FakeWhois whois = new FakeWhois(Map.of("whois.iana.org", "domain: ZZ\nstatus: ACTIVE\n"));

        DomainAgeResult result = checker(whois).check("example.zz");

        assertEquals(DomainAgeResult.Status.UNKNOWN, result.status());
        assertEquals("no WHOIS server known for .zz", result.reason());
    }

    @Test
    void invalidDomainNamesAreNeverSentToAServer() {
        FakeWhois whois = new FakeWhois(Map.of("whois.verisign-grs.com", "Creation Date: 2020-01-01\n"));
        DomainAgeChecker checker = checker(whois);

        assertEquals(DomainAgeResult.Status.UNKNOWN, checker.check("evil.com\r\nhelp").status());
        assertEquals(DomainAgeResult.Status.UNKNOWN, checker.check("").status());
        assertEquals(DomainAgeResult.Status.UNKNOWN, checker.check((String) null).status());
        assertEquals(DomainAgeResult.Status.UNKNOWN, checker.check("localhost").status());
        assertTrue(whois.calls.isEmpty());
    }

    @Test
    void unicodeDomainIsQueriedInPunycode() {
        FakeWhois whois = new FakeWhois(Map.of("whois.verisign-grs.com", "Creation Date: 2020-01-01\n"));

        checker(whois).check("bücher.com");

        assertEquals(List.of("whois.verisign-grs.com xn--bcher-kva.com"), whois.calls);
    }

    @Test
    void timeoutPassedToClientNeverExceedsConfiguredBudget() {
        FakeWhois whois = new FakeWhois(Map.of(
                "whois.iana.org", "refer: whois.nic.io\n",
                "whois.nic.io", "Creation Date: 2020-01-01\n"));

        new DomainAgeChecker(whois, 1500, FIXED_CLOCK).check("example.io");

        assertEquals(2, whois.timeouts.size());
        assertTrue(whois.timeouts.stream().allMatch(t -> t > 0 && t <= 1500), whois.timeouts.toString());
    }

    @Test
    void urlComponentsWithIpOrNoHostAreSkipped() {
        FakeWhois whois = new FakeWhois(Map.of());
        DomainAgeChecker checker = checker(whois);
        UrlAnalyzer urlAnalyzer = new UrlAnalyzer(ConfigLoader.loadDefault());

        assertTrue(checker.check(urlAnalyzer.analyze("http://192.168.1.1/login").components()).isSkipped());
        assertTrue(checker.check(urlAnalyzer.analyze("").components()).isSkipped());
        assertTrue(checker.check((com.phishnet.model.UrlComponents) null).isSkipped());
        assertTrue(whois.calls.isEmpty());
    }

    @Test
    void urlComponentsAreLookedUpByRegistrableDomain() {
        FakeWhois whois = new FakeWhois(Map.of("whois.verisign-grs.com", "Creation Date: 2020-01-01\n"));
        UrlAnalyzer urlAnalyzer = new UrlAnalyzer(ConfigLoader.loadDefault());

        checker(whois).check(urlAnalyzer.analyze("https://login.secure.example.com/path?q=1").components());

        assertEquals(List.of("whois.verisign-grs.com example.com"), whois.calls);
    }

    // --- DomainAgeResult formatting -------------------------------------------

    @Test
    void formatsAgeInDaysMonthsAndYears() {
        assertEquals("0 days", known(0).formatAge());
        assertEquals("1 day", known(1).formatAge());
        assertEquals("29 days", known(29).formatAge());
        assertEquals("59 days", known(59).formatAge());
        assertEquals("1 month", known(60).formatAge()); // floors: 60 days is "1 month", not "2 months"
        assertEquals("5 months", known(180).formatAge());
        assertEquals("23 months", known(730).formatAge());
        assertEquals("2 years", known(731).formatAge());
        assertEquals("31 years", known(11_363).formatAge());
    }

    @Test
    void skippedResultFormatsAsEmpty() {
        assertEquals("", DomainAgeResult.skipped().formatAge());
        assertFalse(DomainAgeResult.skipped().isKnown());
    }

    private static DomainAgeResult known(long days) {
        return DomainAgeResult.known("example.com", TODAY.minusDays(days), days, "whois.test");
    }
}
