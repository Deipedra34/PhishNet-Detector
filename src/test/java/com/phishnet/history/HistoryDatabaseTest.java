package com.phishnet.history;

import com.phishnet.analyzer.UrlAnalyzer;
import com.phishnet.cli.HistoryWriter.TargetType;
import com.phishnet.model.DomainAgeResult;
import com.phishnet.model.PhishNetConfig;
import com.phishnet.model.RiskLevel;
import com.phishnet.model.RiskScore;
import com.phishnet.model.Signal;
import com.phishnet.model.SignalCategory;
import com.phishnet.model.UrlComponents;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Every test gets its own database file under a JUnit temp directory (deleted
 * afterwards), so nothing here touches the real {@code ~/.phishnet} history.
 * Timestamps come from a {@link MutableClock} so ordering and date-range filters
 * are deterministic.
 */
class HistoryDatabaseTest {

    private static final UrlAnalyzer URLS = new UrlAnalyzer(PhishNetConfig.defaultConfig());
    private static final Instant START = Instant.parse("2026-10-01T12:00:00Z");

    @TempDir
    Path tempDir;

    private final ByteArrayOutputStream errBytes = new ByteArrayOutputStream();
    private MutableClock clock;
    private Path file;
    private HistoryDatabase db;

    @BeforeEach
    void setUp() {
        clock = new MutableClock(START);
        file = tempDir.resolve("phishnet-history.db");
        db = new HistoryDatabase(file, true, new PrintStream(errBytes, true, StandardCharsets.UTF_8), clock);
    }

    // --- helpers ----------------------------------------------------------------

    private static RiskScore score(int value, RiskLevel level, String... signalIds) {
        List<Signal> signals = java.util.Arrays.stream(signalIds)
                .map(id -> new Signal(id, SignalCategory.URL, "description of " + id))
                .toList();
        return new RiskScore(value, level, signals, "recommendation");
    }

    private static UrlComponents components(String url) {
        return URLS.analyze(url).components();
    }

    private void recordUrl(String url, RiskLevel level) {
        int value = level == RiskLevel.HIGH ? 80 : level == RiskLevel.MEDIUM ? 45 : 5;
        db.recordUrl(url, components(url), score(value, level), DomainAgeResult.skipped());
        clock.advance(Duration.ofMinutes(1));
    }

    private List<HistoryEntry> all() throws Exception {
        return db.search(HistoryFilter.recent(0));
    }

    private List<String> targets(List<HistoryEntry> entries) {
        return entries.stream().map(HistoryEntry::target).toList();
    }

    private static HistoryFilter targetFilter(String text) {
        return new HistoryFilter(text, null, null, null, null, 0);
    }

    // --- schema / file handling -------------------------------------------------

    @Test
    void firstWriteCreatesDatabaseAndParentDirectories() throws Exception {
        Path nested = tempDir.resolve("a").resolve("b").resolve("history.db");
        HistoryDatabase nestedDb = new HistoryDatabase(nested, true, System.err, clock);
        assertFalse(Files.exists(nested));

        nestedDb.recordUrl("https://example.com", components("https://example.com"),
                score(0, RiskLevel.LOW), DomainAgeResult.skipped());

        assertTrue(Files.isRegularFile(nested));
        assertEquals(1, nestedDb.search(HistoryFilter.recent(0)).size());
    }

    @Test
    void readsOnMissingDatabaseReturnNothingAndCreateNothing() throws Exception {
        assertEquals(List.of(), db.search(HistoryFilter.recent(20)));
        assertEquals(0, db.stats(10).total());
        assertFalse(Files.exists(file));
    }

    @Test
    void reopeningAnExistingDatabaseKeepsItsRows() throws Exception {
        recordUrl("https://example.com", RiskLevel.LOW);

        HistoryDatabase reopened = new HistoryDatabase(file, true, System.err, clock);
        reopened.recordUrl("https://example.org", components("https://example.org"),
                score(0, RiskLevel.LOW), DomainAgeResult.skipped());

        assertEquals(List.of("https://example.org", "https://example.com"),
                targets(reopened.search(HistoryFilter.recent(0))));
    }

    @Test
    void disabledWritesRecordNothing() {
        HistoryDatabase disabled = new HistoryDatabase(file, false, System.err, clock);

        disabled.recordUrl("https://example.com", components("https://example.com"),
                score(0, RiskLevel.LOW), DomainAgeResult.skipped());
        disabled.recordEmail("x.eml", "a@b.com", "hi", score(0, RiskLevel.LOW));

        assertFalse(Files.exists(file));
    }

    @Test
    void writeFailureWarnsOnceAndNeverThrows() throws Exception {
        Path directory = tempDir.resolve("not-a-db");
        Files.createDirectory(directory);
        HistoryDatabase broken = new HistoryDatabase(directory, true,
                new PrintStream(errBytes, true, StandardCharsets.UTF_8), clock);

        broken.recordUrl("https://example.com", components("https://example.com"),
                score(0, RiskLevel.LOW), DomainAgeResult.skipped());
        broken.recordEmail("x.eml", "a@b.com", "hi", score(0, RiskLevel.LOW));

        String err = errBytes.toString(StandardCharsets.UTF_8);
        assertTrue(err.contains("could not write scan history database"), err);
        assertEquals(1, err.lines().count(), "warns once, not once per scan: " + err);
    }

    // --- inserting --------------------------------------------------------------

    @Test
    void urlRecordRoundTripsEveryField() throws Exception {
        String url = "http://login.paypa1-secure.tk/verify";
        DomainAgeResult age = DomainAgeResult.known("paypa1-secure.tk", LocalDate.of(2026, 9, 20), 11, "whois.test");

        db.recordUrl(url, components(url), score(85, RiskLevel.HIGH, "typosquatting", "suspiciousTld"), age);

        List<HistoryEntry> entries = all();
        assertEquals(1, entries.size());
        HistoryEntry entry = entries.get(0);
        assertEquals(1, entry.id());
        assertEquals(START, entry.timestamp());
        assertEquals(TargetType.URL, entry.type());
        assertEquals(url, entry.target());
        assertEquals("paypa1-secure.tk", entry.domain());
        assertNull(entry.subject());
        assertEquals(85, entry.riskScore());
        assertEquals(RiskLevel.HIGH, entry.riskLevel());
        assertEquals(List.of(
                        new HistoryEntry.Reason("typosquatting", "description of typosquatting"),
                        new HistoryEntry.Reason("suspiciousTld", "description of suspiciousTld")),
                entry.reasons());
        assertEquals(11L, entry.domainAgeDays());
    }

    @Test
    void unknownOrSkippedDomainAgeIsStoredAsNull() throws Exception {
        db.recordUrl("https://a.com", components("https://a.com"), score(0, RiskLevel.LOW),
                DomainAgeResult.unknown("a.com", "timed out"));
        db.recordUrl("https://b.com", components("https://b.com"), score(0, RiskLevel.LOW),
                DomainAgeResult.skipped());

        for (HistoryEntry entry : all()) {
            assertNull(entry.domainAgeDays(), entry.target());
        }
    }

    @Test
    void ipUrlStoresHostAsDomain() throws Exception {
        db.recordUrl("http://192.168.1.1/login", components("http://192.168.1.1/login"),
                score(60, RiskLevel.MEDIUM, "ipAddressHost"), DomainAgeResult.skipped());

        assertEquals("192.168.1.1", all().get(0).domain());
    }

    @Test
    void emailRecordStoresSenderDomainAndSubject() throws Exception {
        db.recordEmail("inbox/phish.eml", "Alert@Random-Mailer.INFO", "Verify your account",
                score(70, RiskLevel.HIGH, "senderMismatch"));
        db.recordEmail("raw email", "no-at-sign", "  ", score(0, RiskLevel.LOW));

        List<HistoryEntry> entries = all();
        HistoryEntry withoutDomain = entries.get(0);
        assertEquals("raw email", withoutDomain.target());
        assertNull(withoutDomain.domain());
        assertNull(withoutDomain.subject(), "blank subject is stored as null");

        HistoryEntry phish = entries.get(1);
        assertEquals(TargetType.EMAIL, phish.type());
        assertEquals("inbox/phish.eml", phish.target());
        assertEquals("random-mailer.info", phish.domain());
        assertEquals("Verify your account", phish.subject());
        assertNull(phish.domainAgeDays());
    }

    // --- listing ----------------------------------------------------------------

    @Test
    void listReturnsNewestFirstAndRespectsLimit() throws Exception {
        for (int i = 1; i <= 5; i++) {
            recordUrl("https://site" + i + ".com", RiskLevel.LOW);
        }

        assertEquals(List.of("https://site5.com", "https://site4.com", "https://site3.com"),
                targets(db.search(HistoryFilter.recent(3))));
        assertEquals(5, db.search(HistoryFilter.recent(0)).size(), "limit 0 means no limit");
    }

    @Test
    void scansWithinTheSameMillisecondFallBackToInsertionOrder() throws Exception {
        db.recordUrl("https://first.com", components("https://first.com"), score(0, RiskLevel.LOW),
                DomainAgeResult.skipped());
        db.recordUrl("https://second.com", components("https://second.com"), score(0, RiskLevel.LOW),
                DomainAgeResult.skipped());

        assertEquals(List.of("https://second.com", "https://first.com"), targets(all()));
    }

    @Test
    void timestampsOnWholeSecondsSortCorrectly() throws Exception {
        // Instant.toString() would render these as "...:00Z" and "...:00.500Z", which sort
        // the wrong way round as text; the fixed-precision storage format must not.
        clock.set(Instant.parse("2026-10-01T12:00:00.500Z"));
        recordUrl("https://later.com", RiskLevel.LOW);
        clock.set(Instant.parse("2026-10-01T12:00:00Z"));
        recordUrl("https://earlier.com", RiskLevel.LOW);

        assertEquals(List.of("https://later.com", "https://earlier.com"), targets(all()));
        assertEquals(Instant.parse("2026-10-01T12:00:00Z"), all().get(1).timestamp());
    }

    // --- searching --------------------------------------------------------------

    @Test
    void searchByTargetIsCaseInsensitiveSubstringMatch() throws Exception {
        recordUrl("https://www.PayPal.com/signin", RiskLevel.LOW);
        recordUrl("http://paypal-verify.tk/login", RiskLevel.HIGH);
        recordUrl("https://example.com", RiskLevel.LOW);

        assertEquals(List.of("http://paypal-verify.tk/login", "https://www.PayPal.com/signin"),
                targets(db.search(targetFilter("paypal"))));
        assertEquals(List.of("https://example.com"), targets(db.search(targetFilter("EXAMPLE"))));
        assertEquals(List.of(), targets(db.search(targetFilter("nothing-like-this"))));
    }

    @Test
    void searchByTargetAlsoMatchesDomainAndEmailSubject() throws Exception {
        db.recordEmail("upload.eml", "alert@random-mailer.info", "Your invoice is overdue",
                score(50, RiskLevel.MEDIUM));

        assertEquals(1, db.search(targetFilter("random-mailer")).size(), "matches sender domain");
        assertEquals(1, db.search(targetFilter("invoice")).size(), "matches subject");
        assertEquals(1, db.search(targetFilter("upload")).size(), "matches target label");
    }

    @Test
    void searchTreatsLikeWildcardsLiterally() throws Exception {
        recordUrl("https://shop.com/50%25_off", RiskLevel.LOW);
        recordUrl("https://shop.com/5000-off", RiskLevel.LOW);
        recordUrl("https://shop.com/a_b", RiskLevel.LOW);
        recordUrl("https://shop.com/axb", RiskLevel.LOW);

        assertEquals(List.of("https://shop.com/50%25_off"), targets(db.search(targetFilter("50%"))));
        assertEquals(List.of("https://shop.com/a_b"), targets(db.search(targetFilter("a_b"))));
        assertEquals(List.of(), targets(db.search(targetFilter("%%%"))));
    }

    @Test
    void searchInputIsNeverExecutedAsSql() throws Exception {
        String hostile = "http://evil.tk/?q=x'); DROP TABLE scans; --";
        recordUrl(hostile, RiskLevel.HIGH);
        recordUrl("https://example.com", RiskLevel.LOW);

        assertEquals(List.of(hostile), targets(db.search(targetFilter("'); DROP TABLE scans; --"))));
        assertEquals(List.of(), targets(db.search(targetFilter("' OR '1'='1"))));
        assertEquals(2, all().size(), "table still intact");
    }

    @Test
    void filterByRiskLevel() throws Exception {
        recordUrl("https://low.com", RiskLevel.LOW);
        recordUrl("https://high1.tk", RiskLevel.HIGH);
        recordUrl("https://medium.com", RiskLevel.MEDIUM);
        recordUrl("https://high2.tk", RiskLevel.HIGH);

        assertEquals(List.of("https://high2.tk", "https://high1.tk"),
                targets(db.search(new HistoryFilter(null, RiskLevel.HIGH, null, null, null, 0))));
        assertEquals(List.of("https://medium.com"),
                targets(db.search(new HistoryFilter(null, RiskLevel.MEDIUM, null, null, null, 0))));
    }

    @Test
    void filtersCombineWithAnd() throws Exception {
        clock.set(Instant.parse("2026-10-01T10:00:00Z"));
        recordUrl("https://paypal-old.tk", RiskLevel.HIGH);
        clock.set(Instant.parse("2026-10-05T10:00:00Z"));
        recordUrl("https://paypal-mid.tk", RiskLevel.HIGH);
        recordUrl("https://paypal-low.com", RiskLevel.LOW);
        db.recordEmail("paypal.eml", "x@paypal-mail.tk", "PayPal", score(90, RiskLevel.HIGH));
        clock.set(Instant.parse("2026-10-09T10:00:00Z"));
        recordUrl("https://paypal-new.tk", RiskLevel.HIGH);

        HistoryFilter filter = new HistoryFilter("paypal", RiskLevel.HIGH, TargetType.URL,
                Instant.parse("2026-10-02T00:00:00Z"), Instant.parse("2026-10-09T00:00:00Z"), 0);

        assertEquals(List.of("https://paypal-mid.tk"), targets(db.search(filter)));
    }

    @Test
    void dateRangeIsInclusiveSinceExclusiveUntil() throws Exception {
        Instant boundary = Instant.parse("2026-10-05T00:00:00Z");
        clock.set(boundary.minusMillis(1));
        recordUrl("https://before.com", RiskLevel.LOW);
        clock.set(boundary);
        recordUrl("https://at.com", RiskLevel.LOW);

        assertEquals(List.of("https://at.com"),
                targets(db.search(new HistoryFilter(null, null, null, boundary, null, 0))));
        assertEquals(List.of("https://before.com"),
                targets(db.search(new HistoryFilter(null, null, null, null, boundary, 0))));
    }

    // --- stats ------------------------------------------------------------------

    @Test
    void statsAggregateTotalsLevelsTypesAndFlaggedDomains() throws Exception {
        recordUrl("https://evil.tk/a", RiskLevel.HIGH);
        recordUrl("https://evil.tk/b", RiskLevel.MEDIUM);
        recordUrl("https://evil.tk/c", RiskLevel.HIGH);
        recordUrl("https://bad.ml/x", RiskLevel.HIGH);
        recordUrl("https://bad.ml/y", RiskLevel.MEDIUM);
        recordUrl("https://alpha.tk", RiskLevel.MEDIUM);
        // LOW scans never count as "flagged", however often a domain appears.
        recordUrl("https://example.com/1", RiskLevel.LOW);
        recordUrl("https://example.com/2", RiskLevel.LOW);
        recordUrl("https://example.com/3", RiskLevel.LOW);
        recordUrl("https://example.com/4", RiskLevel.LOW);
        db.recordEmail("phish.eml", "a@mailer.info", "hi", score(70, RiskLevel.HIGH));
        Instant last = clock.instant();

        HistoryStats stats = db.stats(10);

        assertEquals(11, stats.total());
        assertEquals(4L, stats.byRiskLevel().get(RiskLevel.HIGH));
        assertEquals(3L, stats.byRiskLevel().get(RiskLevel.MEDIUM));
        assertEquals(4L, stats.byRiskLevel().get(RiskLevel.LOW));
        assertEquals(10L, stats.byType().get(TargetType.URL));
        assertEquals(1L, stats.byType().get(TargetType.EMAIL));
        assertEquals(START, stats.firstScan());
        assertEquals(last, stats.lastScan());
        // Most flagged first; ties broken alphabetically.
        assertEquals(List.of(
                        new HistoryStats.DomainCount("evil.tk", 3),
                        new HistoryStats.DomainCount("bad.ml", 2),
                        new HistoryStats.DomainCount("alpha.tk", 1),
                        new HistoryStats.DomainCount("mailer.info", 1)),
                stats.topFlaggedDomains());
    }

    @Test
    void statsTopLimitsFlaggedDomains() throws Exception {
        recordUrl("https://a.tk", RiskLevel.HIGH);
        recordUrl("https://b.tk", RiskLevel.HIGH);
        recordUrl("https://c.tk", RiskLevel.HIGH);

        assertEquals(2, db.stats(2).topFlaggedDomains().size());
    }

    @Test
    void statsFillMissingLevelsAndTypesWithZero() throws Exception {
        recordUrl("https://example.com", RiskLevel.LOW);

        HistoryStats stats = db.stats(10);

        assertEquals(0L, stats.byRiskLevel().get(RiskLevel.HIGH));
        assertEquals(0L, stats.byType().get(TargetType.EMAIL));
        assertEquals(List.of(), stats.topFlaggedDomains());
    }

    // --- small helpers ----------------------------------------------------------

    @Test
    void escapeLikeEscapesWildcardsAndTheEscapeCharacter() {
        assertEquals("50\\%\\_off\\\\x", HistoryDatabase.escapeLike("50%_off\\x"));
    }

    @Test
    void defaultPathIsUnderDotPhishnet() {
        Path path = HistoryDatabase.defaultPath();
        assertEquals("phishnet-history.db", path.getFileName().toString());
        assertEquals(".phishnet", path.getParent().getFileName().toString());
    }

    /** A clock tests can move explicitly. */
    private static final class MutableClock extends Clock {
        private Instant now;

        MutableClock(Instant start) {
            this.now = start;
        }

        void set(Instant instant) {
            now = instant;
        }

        void advance(Duration duration) {
            now = now.plus(duration);
        }

        @Override
        public Instant instant() {
            return now;
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }
    }
}
