package com.phishnet.feeds;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Parses raw feed downloads into {@link FeedEntries}. Network-free and static,
 * so it's tested directly against sample feed text.
 */
public final class FeedParser {

    private static final JsonFactory JSON = new JsonFactory();

    private FeedParser() {
    }

    /**
     * OpenPhish's free feed: one URL per line. Blank lines and {@code #} comments
     * are ignored, and lines with no usable host are counted as skipped rather
     * than failing the whole feed.
     */
    public static FeedEntries parseOpenPhish(Reader reader) throws IOException {
        List<String> keys = new ArrayList<>();
        int skipped = 0;
        BufferedReader lines = reader instanceof BufferedReader buffered ? buffered : new BufferedReader(reader);
        String line;
        while ((line = lines.readLine()) != null) {
            String trimmed = line.strip();
            if (trimmed.isEmpty() || trimmed.startsWith("#")) {
                continue;
            }
            Optional<String> key = FeedUrls.normalize(trimmed);
            if (key.isPresent()) {
                keys.add(key.get());
            } else {
                skipped++;
            }
        }
        return FeedEntries.ofKeys(keys, skipped);
    }

    /**
     * PhishTank's {@code online-valid.json}: a JSON array of objects, each with
     * a {@code url} field (plus {@code phish_id}, {@code target}, {@code details}
     * and more, all ignored here). Read as a stream, one entry at a time, since
     * the full database runs to tens of megabytes. Entries without a usable
     * {@code url} are counted as skipped.
     *
     * @throws IOException if the input isn't a JSON array (e.g. an HTML error page)
     */
    public static FeedEntries parsePhishTank(InputStream in) throws IOException {
        List<String> keys = new ArrayList<>();
        int skipped = 0;
        try (JsonParser parser = JSON.createParser(in)) {
            if (parser.nextToken() != JsonToken.START_ARRAY) {
                throw new IOException("unexpected PhishTank feed format: expected a JSON array");
            }
            JsonToken token;
            while ((token = parser.nextToken()) != JsonToken.END_ARRAY) {
                if (token == null) {
                    throw new IOException("PhishTank feed ended unexpectedly");
                }
                if (token != JsonToken.START_OBJECT) {
                    parser.skipChildren();
                    skipped++;
                    continue;
                }
                String url = null;
                while (parser.nextToken() == JsonToken.FIELD_NAME) {
                    String field = parser.currentName();
                    JsonToken value = parser.nextToken();
                    if ("url".equals(field) && value == JsonToken.VALUE_STRING) {
                        url = parser.getText();
                    } else {
                        parser.skipChildren();
                    }
                }
                Optional<String> key = url == null ? Optional.empty() : FeedUrls.normalize(url);
                if (key.isPresent()) {
                    keys.add(key.get());
                } else {
                    skipped++;
                }
            }
        }
        return FeedEntries.ofKeys(keys, skipped);
    }
}
