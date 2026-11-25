package com.phishnet.cli;

import com.phishnet.analyzer.WhoisClient;
import com.phishnet.i18n.Messages;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Locale;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The global --lang option: English, Turkish, and the fallbacks. */
class LanguageOptionTest {

    private record Captured(int exitCode, String stdout, String stderr) {
    }

    private static final WhoisClient OFFLINE_WHOIS = (server, query, timeoutMillis) -> {
        throw new IOException("network disabled in tests");
    };

    /** A URL scan with every side effect off: no WHOIS, ML model, history, or colors. */
    private static final String[] SCAN = {"--url", "http://192.168.1.10/login", "--no-whois", "--no-ml",
            "--no-history", "--no-history-db", "--no-color"};

    @TempDir
    Path tempDir;

    @AfterEach
    void resetLanguage() {
        Messages.setCurrent(null);
    }

    private static Captured run(String... args) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        int exitCode = Main.run(args, new PrintStream(out, true, StandardCharsets.UTF_8),
                new PrintStream(err, true, StandardCharsets.UTF_8), OFFLINE_WHOIS);
        return new Captured(exitCode, out.toString(StandardCharsets.UTF_8), err.toString(StandardCharsets.UTF_8));
    }

    private static String[] scan(String... extra) {
        return Stream.concat(Arrays.stream(SCAN), Arrays.stream(extra)).toArray(String[]::new);
    }

    private static Captured withSystemLocale(String tag, String... args) {
        Locale saved = Locale.getDefault();
        try {
            Locale.setDefault(Locale.forLanguageTag(tag));
            return run(args);
        } finally {
            Locale.setDefault(saved);
        }
    }

    private static void assertEnglishReport(Captured result) {
        assertEquals(0, result.exitCode(), result.stderr());
        assertTrue(result.stdout().contains("Target: http://192.168.1.10/login"), result.stdout());
        assertTrue(result.stdout().contains("Risk Score: "), result.stdout());
        assertTrue(result.stdout().contains("URL uses a raw IP address instead of a domain name"), result.stdout());
        assertTrue(result.stdout().contains("Recommendation: "), result.stdout());
    }

    private static void assertTurkishReport(Captured result) {
        assertEquals(0, result.exitCode(), result.stderr());
        assertTrue(result.stdout().contains("Hedef: http://192.168.1.10/login"), result.stdout());
        assertTrue(result.stdout().contains("Risk Puanı: "), result.stdout());
        assertTrue(result.stdout().contains("URL, alan adı yerine doğrudan bir IP adresi kullanıyor"), result.stdout());
        assertTrue(result.stdout().contains("Öneri: "), result.stdout());
        assertFalse(result.stdout().contains("Risk Score"), result.stdout());
    }

    // --- --lang en / tr / unsupported ------------------------------------------------

    @Test
    void langEnPrintsEnglish() {
        Captured result = run(scan("--lang", "en"));
        assertEnglishReport(result);
        assertEquals("", result.stderr());
    }

    @Test
    void langTrPrintsTurkish() {
        Captured result = run(scan("--lang", "tr"));
        assertTurkishReport(result);
        assertEquals("", result.stderr());
    }

    @Test
    void anUnsupportedLanguageFallsBackToEnglishWithAWarning() {
        Captured result = run(scan("--lang", "xx"));
        assertEnglishReport(result);
        assertTrue(result.stderr().contains("unsupported language 'xx'"), result.stderr());
        assertTrue(result.stderr().contains("en, tr"), result.stderr());
    }

    @Test
    void anUnsupportedLanguageFallsBackToEnglishEvenOnATurkishSystem() {
        Captured result = withSystemLocale("tr-TR", scan("--lang", "de"));
        assertEnglishReport(result);
        assertTrue(result.stderr().startsWith("Warning: unsupported language 'de'"), result.stderr());
    }

    @Test
    void acceptsTheEqualsFormRegionsAndAnyCase() {
        assertTurkishReport(run(scan("--lang=tr")));
        assertTurkishReport(run(scan("--lang", "tr-TR")));
        assertTurkishReport(run(scan("--lang", "TR")));
        assertTurkishReport(run(scan("--lang", "tr_TR")));
    }

    @Test
    void theLastLangWins() {
        assertEnglishReport(run(scan("--lang", "tr", "--lang", "en")));
    }

    // --- default: the system language ------------------------------------------------

    @Test
    void withoutLangTheSystemLanguageIsUsed() {
        assertTurkishReport(withSystemLocale("tr-TR", SCAN));
    }

    @Test
    void withoutLangAnUnsupportedSystemLanguageGivesEnglishSilently() {
        Captured result = withSystemLocale("fr-FR", SCAN);
        assertEnglishReport(result);
        assertEquals("", result.stderr());
    }

    @Test
    void langOverridesTheSystemLanguage() {
        assertEnglishReport(withSystemLocale("tr-TR", scan("--lang", "en")));
    }

    // --- help, subcommands, and machine-readable output --------------------------------

    @Test
    void helpIsTranslatedIncludingPicocliStandardOptions() {
        Captured turkish = run("--lang", "tr", "--help");
        assertEquals(0, turkish.exitCode());
        assertTrue(turkish.stdout().contains("Kullanım:"), turkish.stdout());
        assertTrue(turkish.stdout().contains("Seçenekler:"), turkish.stdout());
        assertTrue(turkish.stdout().contains("Tek bir URL'yi analiz eder"), turkish.stdout());
        assertTrue(turkish.stdout().contains("Bu yardım iletisini gösterir ve çıkar."), turkish.stdout());
        assertTrue(turkish.stdout().contains("--lang=<lang>"), turkish.stdout());

        Captured english = run("--lang", "en", "--help");
        assertTrue(english.stdout().contains("Usage:"), english.stdout());
        assertTrue(english.stdout().contains("Show this help message and exit."), english.stdout());
        assertTrue(english.stdout().contains("--lang=<lang>"), english.stdout());
        assertTrue(english.stdout().contains("Output language: en or tr"), english.stdout());
    }

    @Test
    void subcommandHelpIsTranslatedWhereverLangIsGiven() {
        Captured before = run("--lang", "tr", "serve", "--help");
        Captured after = run("serve", "--help", "--lang", "tr");
        for (Captured result : new Captured[] {before, after}) {
            assertEquals(0, result.exitCode(), result.stderr());
            assertTrue(result.stdout().contains("Dinlenecek TCP portu"), result.stdout());
            assertTrue(result.stdout().contains("--lang=<lang>"), result.stdout());
        }
        Captured nested = run("history", "list", "--help", "--lang", "tr");
        assertTrue(nested.stdout().contains("En son taramaları"), nested.stdout());
    }

    @Test
    void subcommandOutputIsTranslated() {
        String database = tempDir.resolve("history.db").toString();
        Captured stats = run("--lang", "tr", "history", "stats", "--history-db", database, "--no-color");
        assertEquals(0, stats.exitCode(), stats.stderr());
        assertTrue(stats.stdout().contains("Henüz kayıtlı tarama yok"), stats.stdout());
    }

    @Test
    void usageErrorsAreReportedInTheChosenLanguage() {
        Captured result = run("--lang", "tr", "--no-color");
        assertEquals(2, result.exitCode());
        assertTrue(result.stderr().startsWith("Hata: "), result.stderr());
        assertTrue(result.stderr().contains("Kullanım:"), result.stderr());
    }

    @Test
    void aMissingLangValueIsAUsageError() {
        Captured result = run(scan("--lang"));
        assertEquals(2, result.exitCode());
        assertTrue(result.stderr().contains("--lang"), result.stderr());
    }

    @Test
    void quietOutputAndJsonKeysStayEnglish() {
        Captured quiet = run(scan("--lang", "tr", "-q"));
        assertTrue(quiet.stdout().matches("(LOW|MEDIUM|HIGH) \\d+ http://192\\.168\\.1\\.10/login\\R"), quiet.stdout());

        Captured json = run(scan("--lang", "tr", "--json"));
        assertEquals(0, json.exitCode(), json.stderr());
        assertTrue(json.stdout().contains("\"recommendation\" : "), json.stdout());
        assertTrue(json.stdout().matches("(?s).*\"level\" : \"(LOW|MEDIUM|HIGH)\".*"), json.stdout());
        assertTrue(json.stdout().contains("\"description\" : \"URL, alan adı yerine doğrudan bir IP adresi kullanıyor\""),
                json.stdout());
    }

    // --- LanguageOption.select ---------------------------------------------------------

    @Test
    void selectTakesLangOutOfTheArguments() {
        LanguageOption.Selection selection = LanguageOption.select(
                new String[] {"--lang", "tr", "history", "list", "--lang=en", "--limit", "5"}, Locale.ENGLISH);
        assertEquals("en", selection.messages().locale().getLanguage());
        assertNull(selection.unsupportedValue());
        assertArrayEquals(new String[] {"history", "list", "--limit", "5"}, selection.remainingArgs());
    }

    @Test
    void selectLeavesEverythingAfterTheEndOfOptionsMarkerAlone() {
        LanguageOption.Selection selection = LanguageOption.select(
                new String[] {"--url", "x", "--", "--lang", "tr"}, Locale.ENGLISH);
        assertEquals("en", selection.messages().locale().getLanguage());
        assertArrayEquals(new String[] {"--url", "x", "--", "--lang", "tr"}, selection.remainingArgs());
    }
}
