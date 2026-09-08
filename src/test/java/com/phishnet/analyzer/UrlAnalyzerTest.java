package com.phishnet.analyzer;

import com.phishnet.model.PhishNetConfig;
import com.phishnet.model.PhishNetConfig.ScoringConfig;
import com.phishnet.model.Signal;
import com.phishnet.model.UrlAnalysisResult;
import com.phishnet.util.ConfigLoader;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class UrlAnalyzerTest {

    private UrlAnalyzer analyzer;

    @BeforeEach
    void setUp() {
        analyzer = new UrlAnalyzer(ConfigLoader.loadDefault());
    }

    private static Set<String> ids(UrlAnalysisResult result) {
        return result.signals().stream().map(Signal::id).collect(Collectors.toSet());
    }

    // --- happy path / legitimate URLs --------------------------------------

    @Test
    void legitimateUrlHasNoSignals() {
        UrlAnalysisResult result = analyzer.analyze("https://www.paypal.com/signin");
        assertTrue(result.signals().isEmpty(), "unexpected signals: " + result.signals());
        assertEquals("www", result.components().subdomain());
        assertEquals("paypal", result.components().domain());
        assertEquals("com", result.components().tld());
    }

    @Test
    void parsesSchemeHostPathAndQuery() {
        UrlAnalysisResult result = analyzer.analyze("https://mail.google.com/mail/u/0?tab=rm&ogbl=1");
        assertEquals("https", result.components().scheme());
        assertEquals("mail.google.com", result.components().host());
        assertEquals("/mail/u/0", result.components().path());
        assertEquals(Map.of("tab", List.of("rm"), "ogbl", List.of("1")), result.components().queryParams());
    }

    @Test
    void urlWithoutSchemeIsStillParsed() {
        UrlAnalysisResult result = analyzer.analyze("www.microsoft.com/en-us");
        assertEquals("microsoft", result.components().domain());
        assertTrue(result.signals().isEmpty());
    }

    // --- IP address host ----------------------------------------------------

    @Test
    void ipAddressHostIsFlagged() {
        UrlAnalysisResult result = analyzer.analyze("http://192.168.1.1/login");
        assertTrue(ids(result).contains("ipAddressHost"));
        assertTrue(result.components().isIpHost());
    }

    @Test
    void domainHostIsNotFlaggedAsIp() {
        UrlAnalysisResult result = analyzer.analyze("http://example.com/login");
        assertFalse(ids(result).contains("ipAddressHost"));
    }

    @Test
    void outOfRangeOctetsAreNotTreatedAsIp() {
        // Looks IP-shaped but 999 is not a valid octet - not a real IP literal.
        UrlAnalysisResult result = analyzer.analyze("http://999.999.999.999/");
        assertFalse(result.components().isIpHost());
    }

    // --- suspicious TLD -------------------------------------------------------

    @Test
    void suspiciousTldIsFlagged() {
        UrlAnalysisResult result = analyzer.analyze("http://free-prize.tk/claim");
        assertTrue(ids(result).contains("suspiciousTld"));
    }

    @Test
    void commonTldIsNotFlagged() {
        UrlAnalysisResult result = analyzer.analyze("http://example.com/");
        assertFalse(ids(result).contains("suspiciousTld"));
    }

    @Test
    void dotTopTldIsFlagged() {
        UrlAnalysisResult result = analyzer.analyze("http://free-prize-claim.top/winner");
        assertTrue(ids(result).contains("suspiciousTld"));
    }

    @Test
    void dotLoanTldIsFlagged() {
        UrlAnalysisResult result = analyzer.analyze("http://instant-approval.loan/apply");
        assertTrue(ids(result).contains("suspiciousTld"));
    }

    // --- URL shorteners ---------------------------------------------------

    @Test
    void knownShortenerIsFlagged() {
        UrlAnalysisResult result = analyzer.analyze("https://bit.ly/3xample");
        assertTrue(ids(result).contains("urlShortener"));
    }

    @Test
    void nonShortenerDomainIsNotFlagged() {
        UrlAnalysisResult result = analyzer.analyze("https://example.com/3xample");
        assertFalse(ids(result).contains("urlShortener"));
    }

    // --- typosquatting -------------------------------------------------------

    @Test
    void editDistanceTyposquattingIsFlagged() {
        UrlAnalysisResult result = analyzer.analyze("http://paypa1.com/login");
        assertTrue(ids(result).contains("typosquatting"));
    }

    @Test
    void combosquattingBrandSubstringIsFlagged() {
        UrlAnalysisResult result = analyzer.analyze("http://paypal-secure-login.com/login");
        assertTrue(ids(result).contains("typosquatting"));
    }

    @Test
    void brandUsedAsSubdomainOfUnrelatedDomainIsFlagged() {
        UrlAnalysisResult result = analyzer.analyze("http://paypal.secure-verification.com/login");
        assertTrue(ids(result).contains("typosquatting"));
    }

    @Test
    void exactBrandDomainIsNotFlaggedAsTyposquatting() {
        UrlAnalysisResult result = analyzer.analyze("https://paypal.com/signin");
        assertFalse(ids(result).contains("typosquatting"));
    }

    @Test
    void unrelatedDomainIsNotFlaggedAsTyposquatting() {
        UrlAnalysisResult result = analyzer.analyze("https://some-random-blog.com/post/1");
        assertFalse(ids(result).contains("typosquatting"));
    }

    @Test
    void combosquattingWithDigitSubstitutionOnExpandedBrandIsFlagged() {
        // "amaz0n" (zero for 'o') is edit distance 1 from the "amazon" brand entry.
        UrlAnalysisResult result = analyzer.analyze("http://amaz0n-support.xyz/verify");
        assertTrue(ids(result).contains("typosquatting"));
    }

    @Test
    void turkishBankBrandCombosquattingIsFlagged() {
        UrlAnalysisResult result = analyzer.analyze("http://garanti-guvenlik-girisi.com/login");
        assertTrue(ids(result).contains("typosquatting"));
    }

    @Test
    void cryptoExchangeBrandCombosquattingIsFlagged() {
        UrlAnalysisResult result = analyzer.analyze("http://coinbase-wallet-verify.com/login");
        assertTrue(ids(result).contains("typosquatting"));
    }

    // --- homograph / punycode -------------------------------------------------

    @Test
    void punycodeCyrillicLookalikeOfBrandIsFlaggedAsHomograph() throws Exception {
        // Cyrillic а + Latin "pple.com" -> encodes to punycode, decodes back to mixed script.
        String spoofed = "http://" + java.net.IDN.toASCII("аpple.com") + "/login";
        UrlAnalysisResult result = analyzer.analyze(spoofed);
        assertTrue(ids(result).contains("homograph"));
    }

    @Test
    void plainAsciiDomainIsNotFlaggedAsHomograph() {
        UrlAnalysisResult result = analyzer.analyze("https://apple.com/");
        assertFalse(ids(result).contains("homograph"));
    }

    @Test
    void fullyCyrillicLookalikeSkeletonMatchesBrand() {
        // аррӏе.com is entirely Cyrillic (no script mixing) but skeletonizes to "apple".
        String host = "аррӏе.com";
        UrlAnalysisResult result = analyzer.analyze("http://" + host + "/login");
        assertTrue(ids(result).contains("homograph"));
    }

    // --- long / obfuscated URLs ------------------------------------------------

    @Test
    void abnormallyLongUrlIsFlagged() {
        String longPath = "a".repeat(120);
        UrlAnalysisResult result = analyzer.analyze("https://example.com/" + longPath);
        assertTrue(ids(result).contains("longOrObfuscatedUrl"));
    }

    @Test
    void shortUrlIsNotFlaggedAsLong() {
        UrlAnalysisResult result = analyzer.analyze("https://example.com/a");
        assertFalse(ids(result).contains("longOrObfuscatedUrl"));
    }

    @Test
    void excessiveQueryParamsAreFlagged() {
        StringBuilder url = new StringBuilder("https://example.com/?");
        for (int i = 0; i < 12; i++) {
            url.append("p").append(i).append("=v").append(i).append("&");
        }
        UrlAnalysisResult result = analyzer.analyze(url.toString());
        assertTrue(ids(result).contains("excessiveQueryParams"));
    }

    @Test
    void heavilyEncodedUrlIsFlagged() {
        UrlAnalysisResult result = analyzer.analyze(
                "https://example.com/redirect?next=%2F%61%63%63%6F%75%6E%74%2F%6C%6F%67%69%6E");
        assertTrue(ids(result).contains("encodedCharacters"));
    }

    @Test
    void nestedRedirectUrlIsFlagged() {
        UrlAnalysisResult result = analyzer.analyze(
                "https://example.com/redirect?url=https://evil-phish.tk/login");
        assertTrue(ids(result).contains("nestedRedirect"));
    }

    @Test
    void encodedNestedRedirectUrlIsFlagged() {
        UrlAnalysisResult result = analyzer.analyze(
                "https://example.com/redirect?url=https%3A%2F%2Fevil-phish.tk%2Flogin");
        assertTrue(ids(result).contains("nestedRedirect"));
    }

    // --- malformed / empty input -------------------------------------------

    @Test
    void emptyStringIsFlaggedAsMalformed() {
        UrlAnalysisResult result = analyzer.analyze("");
        assertTrue(ids(result).contains("malformedUrl"));
    }

    @Test
    void nullInputIsFlaggedAsMalformed() {
        UrlAnalysisResult result = analyzer.analyze(null);
        assertTrue(ids(result).contains("malformedUrl"));
    }

    @Test
    void blankStringIsFlaggedAsMalformed() {
        UrlAnalysisResult result = analyzer.analyze("   ");
        assertTrue(ids(result).contains("malformedUrl"));
    }

    @Test
    void garbageInputIsFlaggedAsMalformedNotThrown() {
        UrlAnalysisResult result = analyzer.analyze("not a url at all ::: ///");
        assertTrue(ids(result).contains("malformedUrl"));
    }

    @Test
    void schemeOnlyUrlWithNoHostIsFlaggedAsMalformed() {
        UrlAnalysisResult result = analyzer.analyze("mailto:someone@example.com");
        assertTrue(ids(result).contains("malformedUrl"));
    }

    // --- internationalized domain edge case ------------------------------------

    @Test
    void internationalizedDomainWithoutBrandMatchStillFlaggedAsHomograph() {
        // A legitimate-looking but non-ASCII domain with no brand collision: still
        // unusual enough (real brands don't use raw IDN for their primary domain)
        // to be surfaced, just under the generic homograph signal.
        String host = "xn--80ak6aa92e.com"; // valid punycode, arbitrary Cyrillic content
        UrlAnalysisResult result = analyzer.analyze("http://" + host + "/");
        assertTrue(ids(result).contains("homograph"));
    }

    // --- custom config injection --------------------------------------------

    @Test
    void customConfigChangesTyposquattingSensitivity() {
        PhishNetConfig strict = new PhishNetConfig(
                List.of("brandx"),
                List.of(),
                List.of(),
                Map.of(),
                new ScoringConfig(Map.of(), 30, 60, 0, 1000, 100, 100));
        UrlAnalyzer strictAnalyzer = new UrlAnalyzer(strict);

        // distance 1 from "brandx", but max distance configured to 0 -> should not flag
        UrlAnalysisResult result = strictAnalyzer.analyze("http://brandy.com/");
        assertFalse(result.signals().stream().anyMatch(s -> s.id().equals("typosquatting")));
    }
}
