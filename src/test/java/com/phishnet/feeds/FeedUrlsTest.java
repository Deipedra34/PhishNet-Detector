package com.phishnet.feeds;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FeedUrlsTest {

    @ParameterizedTest
    @CsvSource(delimiter = '|', value = {
            "HTTP://WWW.Evil.example:80/login/      | evil.example/login",
            "https://evil.example/login             | evil.example/login",
            "https://evil.example:443               | evil.example/",
            "https://evil.example                   | evil.example/",
            "https://evil.example:8443/x            | evil.example:8443/x",
            "http://evil.example:443/x              | evil.example:443/x",
            "http://evil.example/a?b=1#section      | evil.example/a?b=1",
            "http://evil.example/?                  | evil.example/",
            "evil.example/path                      | evil.example/path",
            "http://user:secret@evil.example/       | evil.example/",
            "http://evil.example./Login.PHP         | evil.example/Login.PHP",
            "http://[2001:db8::1]:8080/x            | [2001:db8::1]:8080/x",
    })
    void normalizesUrlsToComparableKeys(String raw, String expected) {
        assertEquals(Optional.of(expected), FeedUrls.normalize(raw));
    }

    @Test
    void httpAndHttpsVersionsOfAPageShareAKey() {
        assertEquals(FeedUrls.normalize("http://evil.example/x"), FeedUrls.normalize("https://www.evil.example/x/"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "   ", "http:///no-host", "http://bad host.example/"})
    void rejectsInputWithoutAUsableHost(String raw) {
        assertTrue(FeedUrls.normalize(raw).isEmpty());
        assertTrue(FeedUrls.host(raw).isEmpty());
    }

    @Test
    void nullIsRejected() {
        assertTrue(FeedUrls.normalize(null).isEmpty());
    }

    @Test
    void hostDropsSchemePortAndWww() {
        assertEquals(Optional.of("evil.example"), FeedUrls.host("https://WWW.Evil.example.:8443/x"));
    }

    @ParameterizedTest
    @CsvSource(delimiter = '|', value = {
            "evil.example/login        | evil.example",
            "evil.example:8080/x       | evil.example",
            "evil.example/?q=1         | evil.example",
            "[2001:db8::1]:8080/x      | [2001:db8::1]",
    })
    void hostOfKeyStripsPortAndPath(String key, String expected) {
        assertEquals(expected, FeedUrls.hostOfKey(key));
    }
}
