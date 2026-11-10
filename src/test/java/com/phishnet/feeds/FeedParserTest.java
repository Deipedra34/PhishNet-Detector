package com.phishnet.feeds;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FeedParserTest {

    @Test
    void openPhishFeedIsOneUrlPerLine() throws IOException {
        FeedEntries entries = FeedParser.parseOpenPhish(new StringReader(
                "https://login-secure.example/account/verify\n"
                        + "http://www.bank-alerts.example/signin/\r\n"
                        + "https://phish.example:8443/a?id=7\n"));

        assertEquals(3, entries.size());
        assertTrue(entries.containsUrl("login-secure.example/account/verify"));
        assertTrue(entries.containsUrl("bank-alerts.example/signin"));
        assertTrue(entries.containsUrl("phish.example:8443/a?id=7"));
        assertTrue(entries.containsHost("bank-alerts.example"));
        assertTrue(entries.containsHost("phish.example"));
        assertEquals(0, entries.skipped());
    }

    @Test
    void openPhishSkipsBlankLinesCommentsAndUnparsableEntries() throws IOException {
        FeedEntries entries = FeedParser.parseOpenPhish(new StringReader(
                "# OpenPhish community feed\n"
                        + "\n"
                        + "   \n"
                        + "https://one.example/x\n"
                        + "http:///missing-host\n"
                        + "  https://two.example/y  \n"));

        assertEquals(2, entries.size());
        assertTrue(entries.containsUrl("one.example/x"));
        assertTrue(entries.containsUrl("two.example/y"));
        assertEquals(1, entries.skipped());
    }

    @Test
    void openPhishDuplicatesCollapseIntoOneEntry() throws IOException {
        FeedEntries entries = FeedParser.parseOpenPhish(new StringReader(
                "https://dup.example/login\nhttp://www.dup.example/login/\nhttps://DUP.example/login\n"));

        assertEquals(1, entries.size());
    }

    @Test
    void emptyOpenPhishFeedParsesToNoEntries() throws IOException {
        assertEquals(0, FeedParser.parseOpenPhish(new StringReader("")).size());
    }

    @Test
    void phishTankFeedReadsTheUrlOfEveryEntry() throws IOException {
        String json = """
                [
                  {"phish_id": 123, "url": "https://paypal.account-check.example/login",
                   "phish_detail_url": "http://www.phishtank.com/phish_detail.php?phish_id=123",
                   "submission_time": "2026-11-09T10:00:00+00:00", "verified": "yes", "online": "yes",
                   "details": [{"ip_address": "192.0.2.1", "cidr_block": "192.0.2.0/24"}],
                   "target": "PayPal"},
                  {"phish_id": 124, "target": "Other", "url": "http://www.bank.example/secure/"}
                ]
                """;

        FeedEntries entries = FeedParser.parsePhishTank(stream(json));

        assertEquals(2, entries.size());
        assertTrue(entries.containsUrl("paypal.account-check.example/login"));
        assertTrue(entries.containsUrl("bank.example/secure"));
        // phish_detail_url points at PhishTank itself and must never become an entry.
        assertFalse(entries.containsHost("phishtank.com"));
    }

    @Test
    void phishTankEntriesWithoutAUsableUrlAreSkipped() throws IOException {
        String json = """
                [
                  {"phish_id": 1},
                  {"phish_id": 2, "url": null},
                  {"phish_id": 3, "url": ["not", "a", "string"]},
                  {"phish_id": 4, "url": "http:///no-host"},
                  "not an object",
                  {"phish_id": 5, "url": "https://ok.example/"}
                ]
                """;

        FeedEntries entries = FeedParser.parsePhishTank(stream(json));

        assertEquals(1, entries.size());
        assertTrue(entries.containsUrl("ok.example/"));
        assertEquals(5, entries.skipped());
    }

    @Test
    void phishTankRejectsAnythingButAJsonArray() {
        assertThrows(IOException.class, () -> FeedParser.parsePhishTank(stream("<html>Rate limit exceeded</html>")));
        assertThrows(IOException.class, () -> FeedParser.parsePhishTank(stream("{\"error\": \"invalid key\"}")));
    }

    @Test
    void truncatedPhishTankDownloadIsAnError() {
        assertThrows(IOException.class,
                () -> FeedParser.parsePhishTank(stream("[{\"url\": \"https://a.example/\"}, {\"url\": ")));
    }

    private static InputStream stream(String text) {
        return new ByteArrayInputStream(text.getBytes(StandardCharsets.UTF_8));
    }
}
