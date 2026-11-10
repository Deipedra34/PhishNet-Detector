package com.phishnet.feeds;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.time.Duration;
import java.util.Map;

/**
 * Downloads a feed. The only part of the feed pipeline that touches the
 * network, so tests swap in a fake that serves canned feed text.
 */
@FunctionalInterface
public interface FeedFetcher {

    /**
     * Opens {@code uri} for reading. The caller closes the returned stream.
     *
     * @param headers extra request headers (e.g. User-Agent)
     * @param timeout how long to wait for the server to respond
     * @throws IOException on any network error or non-200 response
     */
    InputStream open(URI uri, Map<String, String> headers, Duration timeout) throws IOException;
}
