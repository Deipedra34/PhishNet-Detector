package com.phishnet.feeds;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.Reader;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Parses raw feed downloads into {@link FeedEntries}. Network-free and static,
 * so it's tested directly against sample feed text.
 */
public final class FeedParser {

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
}
