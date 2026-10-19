package com.phishnet.ml;

import com.phishnet.analyzer.UrlAnalyzer;
import com.phishnet.model.DomainAgeResult;
import com.phishnet.model.PhishNetConfig;
import com.phishnet.model.UrlAnalysisResult;
import org.junit.jupiter.api.Test;

import java.time.LocalDate;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FeatureExtractorTest {

    private static final PhishNetConfig CONFIG = PhishNetConfig.defaultConfig();
    private static final UrlAnalyzer ANALYZER = new UrlAnalyzer(CONFIG);
    private static final FeatureExtractor EXTRACTOR = new FeatureExtractor(CONFIG);
    private static final double NAN = Double.NaN;

    private static FeatureVector extract(String url, DomainAgeResult age) {
        return EXTRACTOR.extract(ANALYZER.analyze(url), age);
    }

    private static DomainAgeResult ageDays(String domain, long days) {
        return DomainAgeResult.known(domain, LocalDate.of(2026, 1, 1).minusDays(days), days, "whois.example");
    }

    @Test
    void typosquattedUrlProducesExpectedVector() {
        FeatureVector v = extract("http://paypa1.com/signin/verify-account", ageDays("paypa1.com", 26));

        // url_length, special_chars, dot_count, subdomain_count, ip_host, brand_distance,
        // typosquatting, homograph, suspicious_tld, url_shortener, domain_age_days, https
        assertArrayEquals(new double[] {39, 1, 1, 0, 0, 1, 1, 0, 0, 0, 26, 0}, v.toArray());
    }

    @Test
    void legitimateBrandUrlProducesExpectedVector() {
        FeatureVector v = extract("https://www.paypal.com/signin", ageDays("paypal.com", 9000));

        assertArrayEquals(new double[] {29, 0, 2, 1, 0, FeatureExtractor.BRAND_DISTANCE_CAP, 0, 0, 0, 0, 9000, 1},
                v.toArray());
    }

    @Test
    void ipHostUrlHasIpFlagNoSubdomainsAndUnknownAge() {
        FeatureVector v = extract("http://192.168.1.1/login", DomainAgeResult.skipped());

        assertEquals(1, v.get("ip_host"));
        assertEquals(3, v.get("dot_count"));
        // The analyzer stores the whole IP as the "subdomain" - it must not count as subdomains.
        assertEquals(0, v.get("subdomain_count"));
        assertEquals(FeatureExtractor.BRAND_DISTANCE_CAP, v.get("brand_distance"));
        assertTrue(Double.isNaN(v.get("domain_age_days")));
        assertTrue(v.isUnknown(FeatureVector.NAMES.indexOf("domain_age_days")));
    }

    @Test
    void signalFlagsComeFromTheAnalyzersSignals() {
        assertEquals(1, extract("https://bit.ly/abc", DomainAgeResult.skipped()).get("url_shortener"));
        assertEquals(1, extract("http://free-gift-card.tk/claim", DomainAgeResult.skipped()).get("suspicious_tld"));
        assertEquals(1, extract("http://xn--80ak6aa92e.com/login", DomainAgeResult.skipped()).get("homograph"));

        FeatureVector clean = extract("https://github.com/", DomainAgeResult.skipped());
        assertEquals(0, clean.get("url_shortener"));
        assertEquals(0, clean.get("suspicious_tld"));
        assertEquals(0, clean.get("homograph"));
        assertEquals(0, clean.get("typosquatting"));
    }

    @Test
    void combosquattedDomainContainingBrandHasBrandDistanceZero() {
        FeatureVector v = extract("http://paypal-secure-login.com/", DomainAgeResult.skipped());

        assertEquals(0, v.get("brand_distance"));
        assertEquals(1, v.get("typosquatting"));
    }

    @Test
    void unknownWhoisResultLeavesDomainAgeUnknown() {
        FeatureVector v = extract("https://example.com", DomainAgeResult.unknown("example.com", "timed out"));

        assertTrue(Double.isNaN(v.get("domain_age_days")));
    }

    @Test
    void subdomainCountCountsEveryLabelBeforeTheRegistrableDomain() {
        FeatureVector v = extract("https://a.b.c.example.co.uk/", DomainAgeResult.skipped());

        assertEquals(3, v.get("subdomain_count"));
        assertEquals(5, v.get("dot_count"));
    }

    @Test
    void specialCharCountIgnoresLettersDigitsAndStructuralCharacters() {
        assertEquals(0, FeatureExtractor.specialCharCount("https://www.example.com/a/b.html"));
        assertEquals(6, FeatureExtractor.specialCharCount("http://u@x.com/a-b_c?d=e&f"));
    }

    @Test
    void canExtractIsFalseForMalformedInput() {
        assertFalse(FeatureExtractor.canExtract(ANALYZER.analyze("")));
        assertFalse(FeatureExtractor.canExtract(ANALYZER.analyze("http://")));
        assertTrue(FeatureExtractor.canExtract(ANALYZER.analyze("https://example.com")));
    }

    @Test
    void featureVectorRejectsWrongLengthAndInfiniteValues() {
        assertThrows(IllegalArgumentException.class, () -> new FeatureVector(new double[3]));
        double[] values = new double[FeatureVector.SIZE];
        values[0] = Double.POSITIVE_INFINITY;
        assertThrows(IllegalArgumentException.class, () -> new FeatureVector(values));
        assertThrows(IllegalArgumentException.class, () -> new FeatureVector(new double[FeatureVector.SIZE]).get("nope"));
    }

    @Test
    void featureVectorToStringShowsUnknownAsQuestionMark() {
        double[] values = new double[FeatureVector.SIZE];
        values[0] = 42;
        values[10] = NAN;
        String text = new FeatureVector(values).toString();

        assertTrue(text.startsWith("url_length=42, special_chars=0"), text);
        assertTrue(text.contains("domain_age_days=?"), text);
    }

    @Test
    void extractionUsesTheConfiguredFeatureOrder() {
        UrlAnalysisResult result = ANALYZER.analyze("https://bit.ly/abc");
        FeatureVector v = EXTRACTOR.extract(result, DomainAgeResult.skipped());

        for (int i = 0; i < FeatureVector.SIZE; i++) {
            assertEquals(v.get(i), v.get(FeatureVector.NAMES.get(i)), 0.0, FeatureVector.NAMES.get(i));
        }
    }
}
