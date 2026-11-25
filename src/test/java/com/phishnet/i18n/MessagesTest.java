package com.phishnet.i18n;

import com.phishnet.model.DomainAgeResult;
import com.phishnet.model.RiskLevel;
import com.phishnet.model.RiskScore;
import com.phishnet.model.Signal;
import com.phishnet.model.SignalCategory;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.time.LocalDate;
import java.util.List;
import java.util.Locale;
import java.util.PropertyResourceBundle;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MessagesTest {

    private static final Messages TURKISH = Messages.forLocale(Locale.forLanguageTag("tr"));

    @AfterEach
    void resetLanguage() {
        Messages.setCurrent(null);
    }

    @Test
    void englishIsTheDefault() {
        assertSame(Messages.english(), Messages.current());
        assertEquals(Locale.ENGLISH, Messages.english().locale());
        assertEquals("Target: x", Messages.text("report.target", "x"));
    }

    @Test
    void turkishHasItsOwnText() {
        assertEquals("tr", TURKISH.locale().getLanguage());
        assertEquals("Hedef: x", TURKISH.get("report.target", "x"));
        assertEquals("DÜŞÜK", TURKISH.get("risk.LOW"));
    }

    @Test
    void theRegionDoesNotMatter() {
        assertSame(TURKISH, Messages.forLocale(Locale.forLanguageTag("tr-TR")));
        assertSame(Messages.english(), Messages.forLocale(Locale.US));
    }

    @Test
    void anUnsupportedLanguageGetsEnglishNotTheSystemLanguage() {
        Locale saved = Locale.getDefault();
        try {
            // ResourceBundle's default lookup would fall back to the default locale (Turkish here).
            Locale.setDefault(Locale.forLanguageTag("tr-TR"));
            Messages japanese = Messages.forLocale(Locale.JAPANESE);
            assertEquals(Locale.ENGLISH, japanese.locale());
            assertEquals("Target: x", japanese.get("report.target", "x"));
        } finally {
            Locale.setDefault(saved);
        }
    }

    @Test
    void isSupportedKnowsTheTranslations() {
        assertEquals(List.of("en", "tr"), Messages.LANGUAGES);
        assertTrue(Messages.isSupported("tr"));
        assertTrue(Messages.isSupported("EN"));
        assertEquals(false, Messages.isSupported("de"));
        assertEquals(false, Messages.isSupported(null));
    }

    @Test
    void placeholdersAreFilledInOnePass() {
        // A "{1}" inside an argument (say, a display name) must not be replaced in turn.
        assertEquals("From: {1} <a@b.example>", Messages.english().get("report.email.from", "{1}", "a@b.example"));
        assertEquals("Kimden: {1} <a@b.example>", TURKISH.get("report.email.from", "{1}", "a@b.example"));
    }

    @Test
    void localizedArgumentsAreShownInTheSameLanguage() {
        Text fiveDays = Text.of("domainAge.days.other", 5);
        assertEquals("Domain was registered very recently (5 days ago)",
                Messages.english().get("signal.domainAgeNew", fiveDays));
        assertEquals("Alan adı çok yakın zamanda kaydedilmiş (5 gün önce)", TURKISH.get("signal.domainAgeNew", fiveDays));
    }

    @Test
    void pluralsPickOneOrOther() {
        assertEquals("1 second", Messages.english().plural("duration.second", 1));
        assertEquals("2 seconds", Messages.english().plural("duration.second", 2));
        assertEquals("2 saniye", TURKISH.plural("duration.second", 2));
    }

    @Test
    void scanResultsKeepTheirEnglishTextAndRenderInAnyLanguage() {
        Signal signal = new Signal("sslExpired", SignalCategory.SSL, Text.of("signal.sslExpired"), "notAfter=x");
        assertEquals("TLS certificate has expired", signal.description());
        assertEquals("TLS sertifikasının süresi dolmuş", signal.description(TURKISH));

        Signal plain = new Signal("custom", SignalCategory.URL, "Plain description", null);
        assertEquals("Plain description", plain.description(TURKISH));

        RiskScore standard = new RiskScore(80, RiskLevel.HIGH, List.of(signal),
                Messages.english().get("recommendation.HIGH"));
        assertTrue(standard.recommendation(TURKISH).startsWith("Yüksek oltalama riski."));
        RiskScore custom = new RiskScore(80, RiskLevel.HIGH, List.of(), "Custom advice");
        assertEquals("Custom advice", custom.recommendation(TURKISH));

        DomainAgeResult age = DomainAgeResult.known("example.com", LocalDate.of(2000, 1, 1), 9000, "whois.example");
        assertEquals("24 years", age.formatAge());
        assertEquals("24 yıl", age.formatAge(TURKISH));
        DomainAgeResult unknown = DomainAgeResult.unknown("example.com", Text.of("domainAge.reason.timeout"));
        assertEquals("WHOIS lookup timed out", unknown.reason());
        assertEquals("WHOIS sorgusu zaman aşımına uğradı", unknown.reason(TURKISH));
        assertEquals("bilinmiyor", unknown.formatAge(TURKISH));
    }

    @Test
    void everyKeyIsTranslatedWithTheSamePlaceholders() throws IOException {
        PropertyResourceBundle english = load("/i18n/messages.properties");
        PropertyResourceBundle turkish = load("/i18n/messages_tr.properties");
        Set<String> englishKeys = new TreeSet<>(english.keySet());
        Set<String> turkishKeys = new TreeSet<>(turkish.keySet());
        assertEquals(englishKeys, turkishKeys, "messages_tr.properties must have exactly the English keys");

        Pattern placeholder = Pattern.compile("\\{\\d+}|\\$\\{[A-Z-]+}|%n");
        for (String key : englishKeys) {
            assertEquals(placeholders(placeholder, english.getString(key)),
                    placeholders(placeholder, turkish.getString(key)), "placeholders of " + key);
        }
    }

    private static Set<String> placeholders(Pattern pattern, String text) {
        Set<String> found = new TreeSet<>();
        Matcher matcher = pattern.matcher(text);
        while (matcher.find()) {
            found.add(matcher.group());
        }
        return found;
    }

    private static PropertyResourceBundle load(String resource) throws IOException {
        try (InputStream in = MessagesTest.class.getResourceAsStream(resource)) {
            return new PropertyResourceBundle(new InputStreamReader(in, StandardCharsets.UTF_8));
        }
    }
}
